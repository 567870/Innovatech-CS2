# ==============================================================================
# FILE: 06-web-app.tf
# RESPONSIBILITY: Application Load Balancer & Multi-AZ Flash Ticket Auto Scaling
# REQUIREMENTS: REQ-NCA-P2-01 (Design-for-Failure), REQ-NCA-P1-05 (Patch Tags)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. APPLICATION LOAD BALANCER & TARGET GROUP
# ------------------------------------------------------------------------------
resource "aws_lb" "main_alb" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1a.id, aws_subnet.public_1b.id]

  tags = { Name = "Main-ALB" }
}

resource "aws_lb_target_group" "web_tg" {
  name_prefix = "webtg-"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path                = "/"
    port                = "8080"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    timeout             = 3
    interval            = 15
    matcher             = "200"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "Web-Target-Group" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

# ------------------------------------------------------------------------------
# 2. LAUNCH TEMPLATE & USER DATA BOOTSTRAP
# ------------------------------------------------------------------------------
resource "aws_launch_template" "web_lt" {
  name_prefix   = "web-launch-template-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.ec2_instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.web_profile.arn
  }

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data = base64encode(<<-EOF
#!/bin/bash
dnf update -y
dnf install -y docker
systemctl enable --now docker

# Create isolated bridge network for containers
docker network create web-net

# Prepare custom NGINX stub_status configuration for Prometheus metrics
mkdir -p /home/ec2-user/nginx-conf
cat << 'CONF' > /home/ec2-user/nginx-conf/status.conf
server {
    listen 8080;
    location /stub_status {
        stub_status;
        access_log off;
        allow all;
    }
}
CONF

# 1. Run NGINX Web Server on port 80
docker run -d --name nginx --restart always --network web-net -p 80:80 \
  -v /home/ec2-user/nginx-conf/status.conf:/etc/nginx/conf.d/status.conf:ro \
  nginx:latest

# 2. Run NGINX Prometheus Exporter scraping NGINX on port 8080 and exposing 9113
docker run -d --name nginx-exporter --restart always --network web-net -p 9113:9113 \
  nginx/nginx-prometheus-exporter:latest \
  -nginx.scrape-uri=http://nginx:8080/stub_status

# 3. Run Prometheus Node Exporter on port 9100 for hardware metrics
docker run -d --name node-exporter --restart always \
  --net="host" --pid="host" \
  -v "/:/host:ro,rslave" \
  prom/node-exporter:latest \
  --path.rootfs=/host

# 4. Flash Ticket Sales Python App (Port 8080)
mkdir -p /opt/ticket-app
cd /opt/ticket-app

cat << 'PY' > app.py
import os
import time
import uuid
import random
import hashlib
import threading
import urllib.request
import urllib.parse
from flask import Flask, request
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# ---------------- Prometheus metrics ----------------
TICKETS_SOLD = Counter('tickets_sold_total', 'Total number of flash tickets sold')
LOAD_TESTS = Counter('load_tests_started_total', 'Load tests started', ['mode'])
LOAD_SENT = Counter('load_test_requests_total', 'Buy requests sent by the load test', ['result'])
LOAD_RECEIVED = Counter('load_requests_received_total', 'Load-test buy requests handled by this server')
LOAD_ACTIVE = Gauge('load_test_active', '1 if this server is running a load test')

EXPECTED_INSTANCES = 2
OVERHEAD_MS = 6
MAX_ITERATIONS = 3000000
LOCAL_URL = 'http://127.0.0.1:8080/buy'

LOAD_PROFILES = {
    'light':  {'label': 'Light load test',      'cpu': 0.20, 'seconds': 120, 'rps': 5,  'threads': 2},
    'medium': {'label': 'Medium load test',     'cpu': 0.45, 'seconds': 180, 'rps': 10, 'threads': 4},
    'heavy':  {'label': 'Very heavy load test', 'cpu': 0.70, 'seconds': 600, 'rps': 20, 'threads': 8},
}

_state = {'active': False, 'mode': None, 'end': 0.0, 'id': None, 'stop': None}
_seen_ids = {}
_stopped_ids = set()
_lock = threading.Lock()

def _calibrate():
    n = 20000
    best = None
    for _ in range(3):
        t = time.perf_counter()
        hashlib.pbkdf2_hmac('sha256', b'x', b'y', n)
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    return n / (best * 1000.0)

def _finish(test_id):
    with _lock:
        if _state['id'] == test_id:
            _state['active'] = False
            LOAD_ACTIVE.set(0)

def _traffic(test_id, base_url, total_rps, threads_n, iterations, end_time, stop_evt):
    interval = threads_n / float(total_rps)
    urls = [base_url + '/buy', LOCAL_URL]
    headers = {'X-Load-Id': test_id, 'X-Load-Iterations': str(iterations)}
    while time.time() < end_time and not stop_evt.is_set():
        started = time.time()
        data = urllib.parse.urlencode({'quantity': random.randint(1, 5), 'mode': 'normal'}).encode()
        result = 'error'
        for i, url in enumerate(urls):
            try:
                req = urllib.request.Request(url, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                    if resp.headers.get('X-Load-Stop') == '1':
                        stop_evt.set()
                        result = 'stopped'
                    else:
                        result = 'ok' if i == 0 else 'fallback_local'
                break
            except Exception:
                continue
        LOAD_SENT.labels(result=result).inc()
        stop_evt.wait(max(0.0, interval - (time.time() - started)))
    _finish(test_id)

def start_load(mode, base_url):
    profile = LOAD_PROFILES[mode]
    with _lock:
        if _state['active'] and time.time() < _state['end']:
            left = int(_state['end'] - time.time())
            return False, f"A {_state['mode']} load test is already running ({left}s left)."
        per_server_rps = profile['rps']
        total_rps = per_server_rps * EXPECTED_INSTANCES
        ncpu = os.cpu_count() or 1
        cost_ms = max(2.0, profile['cpu'] * ncpu / per_server_rps * 1000.0 - OVERHEAD_MS)
        iterations = min(int(_calibrate() * cost_ms), MAX_ITERATIONS)
        test_id = uuid.uuid4().hex
        end_time = time.time() + profile['seconds']
        stop_evt = threading.Event()
        _state.update(active=True, mode=mode, end=end_time, id=test_id, stop=stop_evt)
        _seen_ids[test_id] = time.time()
        LOAD_ACTIVE.set(1)
        LOAD_TESTS.labels(mode=mode).inc()
    for _ in range(profile['threads']):
        threading.Thread(
            target=_traffic,
            args=(test_id, base_url, total_rps, profile['threads'], iterations, end_time, stop_evt),
            daemon=True
        ).start()
    def _watch():
        stop_evt.wait(profile['seconds'])
        stop_evt.set()
        _finish(test_id)
    threading.Thread(target=_watch, daemon=True).start()
    return True, (f"{profile['label']} started for {profile['seconds']}s: about {total_rps} "
                  f"ticket-purchase requests/sec through the load balancer.")

def stop_load():
    now = time.time()
    with _lock:
        local = _state['active'] and now < _state['end']
        if local and _state['stop'] is not None:
            _state['stop'].set()
            _state['active'] = False
            LOAD_ACTIVE.set(0)
        recent = [i for i, t in _seen_ids.items() if now - t < 15]
        _stopped_ids.update(recent)
        if local or recent:
            return True, "Load test stopped. Ticket traffic and CPU will return to normal."
    return False, "No active load test found. If one is running, click Stop again."

# Safe Base64-encoded HTML UI to avoid raw HTML tags in scripts
import base64
HTML_PAGE = (
    "<div style='font-family:Segoe UI,sans-serif;background:#f8f9fa;display:flex;justify-content:center;"
    "align-items:center;min-height:100vh;margin:0;'>"
    "<div style='background:white;padding:40px;border-radius:12px;box-shadow:0 10px 20px rgba(0,0,0,0.1);"
    "text-align:center;max-width:440px;width:100%;'>"
    "<h1>Flash Ticket Sale</h1><p>Innovatech Exclusive Event Portal</p>"
    "<form action='/buy' method='POST'>"
    "<div style='margin-bottom:20px;'><label style='display:block;margin-bottom:8px;font-weight:bold;'>Number of Tickets</label>"
    "<input type='number' name='quantity' min='1' max='10' value='1' required style='width:100px;padding:10px;font-size:18px;text-align:center;'></div>"
    "<div style='text-align:left;margin-bottom:25px;'>"
    "<label style='display:block;margin-bottom:8px;font-weight:bold;'>Purchase Mode</label>"
    "<label style='display:block;padding:8px;'><input type='radio' name='mode' value='normal' checked> Normal purchase</label>"
    "<label style='display:block;padding:8px;'><input type='radio' name='mode' value='light'> Light load test (~10 req/s)</label>"
    "<label style='display:block;padding:8px;'><input type='radio' name='mode' value='medium'> Medium load test (~20 req/s)</label>"
    "<label style='display:block;padding:8px;'><input type='radio' name='mode' value='heavy'> Heavy load test (~70% CPU, triggers ASG)</label>"
    "<label style='display:block;padding:8px;'><input type='radio' name='mode' value='stop'> Stop load test</label>"
    "</div>"
    "<button type='submit' style='background:#e84393;color:white;border:none;padding:15px 30px;font-size:18px;font-weight:bold;border-radius:6px;cursor:pointer;width:100%;'>SUBMIT</button>"
    "</form></div></div>"
)

@app.route('/')
def home():
    return HTML_PAGE, 200

def _handle_load_request(load_id):
    now = time.time()
    with _lock:
        if load_id in _stopped_ids:
            return 'stopped', 200, {'X-Load-Stop': '1'}
        _seen_ids[load_id] = now
        for k in [k for k, t in _seen_ids.items() if now - t > 3600]:
            del _seen_ids[k]
    try:
        quantity = int(request.form.get('quantity', 1))
    except ValueError:
        quantity = 1
    try:
        iterations = int(request.headers.get('X-Load-Iterations', 1000))
    except ValueError:
        iterations = 1000
    iterations = max(1000, min(iterations, MAX_ITERATIONS))
    LOAD_RECEIVED.inc()
    TICKETS_SOLD.inc(quantity)
    hashlib.pbkdf2_hmac('sha256', b'ticket', b'flash-salt', iterations)
    return 'ok', 200

@app.route('/buy', methods=['POST'])
def buy_ticket():
    load_id = request.headers.get('X-Load-Id')
    if load_id:
        return _handle_load_request(load_id)
    mode = request.form.get('mode', 'normal')
    if mode == 'stop':
        _, msg = stop_load()
        return f"<div style='font-family:sans-serif;text-align:center;margin-top:100px;'><h2>{msg}</h2><a href='/'>Back</a></div>", 200
    try:
        quantity = int(request.form.get('quantity', 1))
    except ValueError:
        quantity = 1
    if mode not in LOAD_PROFILES:
        mode = 'normal'
    TICKETS_SOLD.inc(quantity)
    load_msg = ''
    if mode != 'normal':
        proto = request.headers.get('X-Forwarded-Proto', 'http')
        base_url = f"{proto}://{request.host}"
        _, msg = start_load(mode, base_url)
        load_msg = f"<p style='color:#d63031;font-weight:bold;'>{msg}</p>"
    return f"<div style='font-family:sans-serif;text-align:center;margin-top:100px;'><h2>{quantity} Ticket(s) Purchased!</h2>{load_msg}<a href='/'>Buy More</a></div>", 200

@app.route('/stop', methods=['POST'])
def stop():
    stopped, msg = stop_load()
    return {'stopped': stopped, 'message': msg}, 200

@app.route('/status')
def status():
    with _lock:
        active = _state['active'] and time.time() < _state['end']
        left = max(0, int(_state['end'] - time.time())) if active else 0
        return {'load_active': active, 'mode': _state['mode'] if active else None, 'seconds_left': left}, 200

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
PY

cat << 'REQ' > requirements.txt
flask
prometheus-client
REQ

cat << 'DOCKER' > Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
DOCKER

docker build -t flash-ticket-app .
docker run -d --name ticket-app --restart always -p 8080:8080 flash-ticket-app
EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "Web-ASG-Server"
      PatchGroup = "Innovatech-Fleet"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ------------------------------------------------------------------------------
# 3. AUTO SCALING GROUP & CPU SCALING POLICY (REQ-NCA-P2-01)
# ------------------------------------------------------------------------------
resource "aws_autoscaling_group" "web_asg" {
  name_prefix         = "web-asg-"
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2
  target_group_arns   = [aws_lb_target_group.web_tg.arn]
  vpc_zone_identifier = [aws_subnet.private_web_1a.id, aws_subnet.private_web_1b.id]

  # Do not launch instances until NAT + private routing are fully available
  depends_on = [
    aws_nat_gateway.nat,
    aws_route_table_association.private_mgmt_assoc,
    aws_route_table_association.private_web_1a_assoc,
    aws_route_table_association.private_web_1b_assoc
  ]

  launch_template {
    id      = aws_launch_template.web_lt.id
    version = "$Latest"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "web_cpu_policy" {
  name                   = "web-cpu-autoscaling"
  autoscaling_group_name = aws_autoscaling_group.web_asg.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}