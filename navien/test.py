import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion, ReasonCodes
import re
import json
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

# ==========================================================
# Config
# ==========================================================
def load_config():
    try:
        with open('/data/options.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print("Failed to load config:", e)
        raise

config = load_config()

MQTT_SERVER = config["MQTT"]["server"]
MQTT_PORT = int(config["MQTT"]["port"])
MQTT_USERNAME = config["MQTT"]["username"]
MQTT_PASSWORD = config["MQTT"]["password"]

ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

# ==========================================================
# Device
# ==========================================================
class Device:
    def __init__(self, device_name, device_id, device_subid, device_class,
                 child_device=None, mqtt_discovery=True, optional_info=None):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_class = device_class
        self.device_unique_id = f"rs485_{device_id}_{device_subid}"

        self._status_messages_map = defaultdict(list)
        self._command_messages_map = defaultdict(list)

        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info or {}

    # -------------------------------
    # Registration
    # -------------------------------
    def register_status(self, message_flag, attr_name, topic_class, regex, process_func):
        self._status_messages_map[message_flag].append({
            'attr_name': attr_name,
            'topic_class': topic_class,
            'regex': regex,
            'process_func': process_func
        })

    def register_command(self, message_flag, attr_name, topic_class, process_func):
        self._command_messages_map[message_flag].append({
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        })

    # -------------------------------
    # Helpers
    # -------------------------------
    def get_status_attr_list(self):
        return list({s['attr_name']
                     for lst in self._status_messages_map.values()
                     for s in lst})

    def get_command_payload_byte(self, attr_name, value):
        for flag, cmds in self._command_messages_map.items():
            for cmd in cmds:
                if cmd['attr_name'] == attr_name:
                    return flag, cmd['process_func'](value)
        return None, None

    # -------------------------------
    # MQTT Discovery
    # -------------------------------
    def get_mqtt_discovery_payload(self):
        payload = {
            "~": f"{ROOT_TOPIC_NAME}/{self.device_class}/{self.device_name}",
            "name": self.device_name,
            "unique_id": self.device_unique_id,
            "availability_topic": "~/availability",
            "state_topic": "~/power",
            "command_topic": "~/power/set",
            "preset_mode_state_topic": "~/preset_mode",
            "preset_mode_command_topic": "~/preset_mode/set",
            "device": {
                "identifiers": [self.device_unique_id],
                "name": self.device_name,
                "manufacturer": "Navien",
                "model": "RS485"
            }
        }
        payload.update(self.optional_info)
        return json_dumps(payload, ensure_ascii=False)

    # -------------------------------
    # Payload parsing (핵심)
    # -------------------------------
    def parse_payload(self, payload_dict):
        result = {}
        flag = payload_dict['message_flag']
        data = payload_dict['data']

        for status in self._status_messages_map.get(flag, []):
            m = re.match(status['regex'], data)
            if not m:
                continue

            value = status['process_func'](m.group(1) if m.groups() else None)
            topic = f"{ROOT_TOPIC_NAME}/{self.device_class}/{self.device_name}/{status['attr_name']}"
            result[topic] = value

        return result

# ==========================================================
# Wallpad
# ==========================================================
class Wallpad:
    def __init__(self):
        self._device_list = []

        self.mqtt_client = mqtt.Client(
            client_id="rs485_2mqtt",
            protocol=mqtt.MQTTv5,
            callback_api_version=CallbackAPIVersion.VERSION2
        )

        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_disconnect = self.on_disconnect

        self.mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, MQTT_PORT)

    # -------------------------------
    # MQTT callbacks
    # -------------------------------
    def on_connect(self, client, userdata, flags, reasonCode, properties):
        print("MQTT connect:", reasonCode)
        if reasonCode.value == 0:
            self.register_mqtt_discovery()
            self.subscribe_topics()
        else:
            print("MQTT connection failed:", reasonCode)

    def on_disconnect(self, client, userdata, reasonCode, properties):
        print("MQTT disconnected:", reasonCode, "(code:", reasonCode.value, ")")


    # -------------------------------
    # Subscribe / Discovery
    # -------------------------------
    def subscribe_topics(self):
        topics = [f"{ROOT_TOPIC_NAME}/dev/raw"]
        for d in self._device_list:
            for attr in d.get_status_attr_list():
                topics.append(f"{ROOT_TOPIC_NAME}/{d.device_class}/{d.device_name}/{attr}/set")
        self.mqtt_client.subscribe([(t, 1) for t in topics])

    def register_mqtt_discovery(self):
        for d in self._device_list:
            if not d.mqtt_discovery:
                continue
            topic = f"{HOMEASSISTANT_ROOT_TOPIC_NAME}/{d.device_class}/{d.device_unique_id}/{d.device_name}/config"
            self.mqtt_client.publish(topic, d.get_mqtt_discovery_payload(), qos=1, retain=True)

    # -------------------------------
    # RS485 helpers
    # -------------------------------
    @staticmethod
    def xor(hex_arr):
        return format(reduce(lambda x, y: x ^ y, [int(h, 16) for h in hex_arr]), '02x')

    @staticmethod
    def add(hex_arr):
        return format(sum(int(h, 16) for h in hex_arr), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload):
        arr = [payload[i:i+2] for i in range(0, len(payload), 2)]
        try:
            return (
                int(arr[4], 16) + 7 == len(arr) and
                cls.xor(arr[:-2]) == arr[-2] and
                cls.add(arr[:-1]) == arr[-1]
            )
        except Exception:
            return False

    # -------------------------------
    # Message handler
    # -------------------------------
    def on_message(self, client, userdata, msg):
        if msg.topic != f"{ROOT_TOPIC_NAME}/dev/raw":
            self.handle_command(msg)
            return

        for part in msg.payload.split(b'\xf7')[1:]:
            payload = 'f7' + part.hex()
            if not self.is_valid(payload):
                client.publish(f"{ROOT_TOPIC_NAME}/dev/error", payload)
                continue

            m = re.match(
                r'f7(?P<device_id>0e|12|32|33|36)'
                r'(?P<device_subid>[0-9a-f]{2})'
                r'(?P<message_flag>[0-9a-f]{2})'
                r'(?:[0-9a-f]{2})'
                r'(?P<data>[0-9a-f]*)',
                payload
            )
            if not m:
                continue

            d = self.get_device(device_id=m['device_id'], device_subid=m['device_subid'])
            parsed = d.parse_payload(m.groupdict())
            for topic, value in parsed.items():
                client.publish(topic, value, qos=1)

    def handle_command(self, msg):
        parts = msg.topic.split('/')
        device_name, attr = parts[2], parts[3]
        device = self.get_device(device_name=device_name)

        flag, payload = device.get_command_payload_byte(attr, msg.payload.decode())
        if flag:
            self.mqtt_client.publish(f"{ROOT_TOPIC_NAME}/dev/command", flag + payload, qos=2)

    # -------------------------------
    # Device management
    # -------------------------------
    def add_device(self, *args, **kwargs):
        d = Device(*args, **kwargs)
        self._device_list.append(d)
        return d

    def get_device(self, **kwargs):
        for d in self._device_list:
            if all(getattr(d, k) == v for k, v in kwargs.items()):
                return d
        raise LookupError(kwargs)

    def loop(self):
        self.mqtt_client.loop_forever()

# ==========================================================
# Device setup
# ==========================================================
packet_2_preset = {
    "01": "바이패스",
    "03": "전열",
    "04": "오토",
    "05": "공기청정",
    "00": "off"
}
preset_2_packet = {v: k for k, v in packet_2_preset.items()}

optional_info = {
    "preset_modes": list(preset_2_packet.keys())
}

wallpad = Wallpad()

fan = wallpad.add_device(
    device_name="환풍기",
    device_id="32",
    device_subid="01",
    device_class="fan",
    optional_info=optional_info
)

fan.register_status("81", "power", "state_topic", r'00(0[01])', lambda v: "ON" if v == "01" else "OFF")
fan.register_status("81", "preset_mode", "preset_mode_state_topic", r'000[01](0[0-5])', lambda v: packet_2_preset[v])

fan.register_command("41", "power", "command_topic", lambda v: "01" if v == "ON" else "00")
fan.register_command("43", "preset_mode", "preset_mode_command_topic", lambda v: preset_2_packet[v])

wallpad.loop()
