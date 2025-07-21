import paho.mqtt.client as mqtt
import docker
import ssl
import json
import yaml
import platform
import argparse

hostname = platform.node()
topic = ""

required_labels = {'app_type', 'app_name', 'alert_action', 'hostname'}

dclient = docker.DockerClient(base_url='unix://var/run/docker.sock')

def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected to MQTT with result code {reason_code}")
    client.subscribe(topic)

def on_message(client, userdata, msg):
    alert = json.loads(msg.payload)
    handle_alert(alert)

def handle_alert(alert):
    alerts = alert['alerts']
    for a in alerts:
        labels = a['labels']
        label_keys = set(labels.keys())
        if not required_labels.issubset(label_keys):
            print("DEBUG: Not enough labels to operate on alert")
            return
        if labels['hostname'] != hostname:
            print("Alert is for a different host, ignoring")
            return
        if labels['app_type'] == 'docker':
            container_name = labels['app_name']
            try:
                container = dclient.containers.get(container_name)
            except docker.errors.NotFound:
                print(f"Container {container_name} not found")
                return
            if labels['alert_action'] == "restart":
                print(f"Restarting container {container_name}")
                container.restart()

def main() -> None:
    parser = argparse.ArgumentParser(description="MQTT ops alerts daemon")
    parser.add_argument("config", nargs='?', type=argparse.FileType('r'), default="config.yaml", \
                        help="path to config file")
    args = parser.parse_args()
    config = yaml.safe_load(args.config)

    print(f"Current Hostname: {hostname}")
    global topic
    topic = config['mqtt']['topic']

    mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    mqttc.reconnect_delay_set(min_delay = 1, max_delay = 30)
    if 'username' in config['mqtt']:
        mqttc.username_pw_set(username=config['mqtt']['username'], password=config['mqtt']['password'])
    print("Connecting to mqtt")
    if 'use_tls' in config['mqtt'] and config['mqtt']['use_tls']:
        mqttc.tls_set(certfile=None,
                keyfile=None,
                cert_reqs=ssl.CERT_REQUIRED)
        print("Using TLS for MQTT connection")
    mqttc.connect(config['mqtt']['host'], config['mqtt']['port'], 30)
    mqttc.loop_forever()
