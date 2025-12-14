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

# ==========================================================
# 가스밸브 (Gas Valve)
# ==========================================================

gas_optional_info = {
    "optimistic": "false"
}

gas_valve = wallpad.add_device(
    device_name="가스 차단기",
    device_id="12",
    device_subid="01",
    device_class="switch",
    optional_info=gas_optional_info
)

# 가용성 상태 (항상 online으로 표시)
gas_valve.register_status(
    message_flag="01",
    attr_name="availability",
    topic_class="availability_topic",
    regex=r'()',
    process_func=lambda v: "online"
)

# 전원 상태 (81 플래그)
gas_valve.register_status(
    message_flag="81",
    attr_name="power",
    topic_class="state_topic",
    regex=r'00(0[12])',
    process_func=lambda v: "ON" if v == "01" else "OFF"
)

# 전원 상태 (c1 플래그, 일부 시스템에서 중복 보고)
gas_valve.register_status(
    message_flag="c1",
    attr_name="power",
    topic_class="state_topic",
    regex=r'00(0[12])',
    process_func=lambda v: "ON" if v == "01" else "OFF"
)

# 제어 명령 (ON/OFF)
gas_valve.register_command(
    message_flag="41",
    attr_name="power",
    topic_class="command_topic",
    process_func=lambda v: "01" if v == "ON" else "00"
)

# ==========================================================
# 조명 (Lights)
# ==========================================================

light_optional_info = {"optimistic": "false"}

# 개별 조명 등록
거실등1 = wallpad.add_device("거실등1", "0e", "11", "light", optional_info=light_optional_info)
거실등2 = wallpad.add_device("거실등2", "0e", "12", "light", optional_info=light_optional_info)
간접등  = wallpad.add_device("간접등",  "0e", "13", "light", optional_info=light_optional_info)
주방등  = wallpad.add_device("주방등",  "0e", "14", "light", optional_info=light_optional_info)
식탁등  = wallpad.add_device("식탁등",  "0e", "15", "light", optional_info=light_optional_info)
복도등  = wallpad.add_device("복도등",  "0e", "16", "light", optional_info=light_optional_info)
안방등  = wallpad.add_device("안방등",  "0e", "21", "light", optional_info=light_optional_info)
대피공간등 = wallpad.add_device("대피공간등", "0e", "22", "light", optional_info=light_optional_info)

# 그룹 조명 등록 (엔티티로 노출)
거실등전체 = wallpad.add_device(
    device_name="거실등 전체",
    device_id="0e",
    device_subid="1f",
    device_class="light",
    child_device=[거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등]
)

안방등전체 = wallpad.add_device(
    device_name="안방등 전체",
    device_id="0e",
    device_subid="2f",
    device_class="light",
    child_device=[안방등, 대피공간등]
)

# 그룹 가용성 상태
거실등전체.register_status("01", "availability", "availability_topic", r'()', lambda v: "online")
안방등전체.register_status("01", "availability", "availability_topic", r'()', lambda v: "online")

# 개별 조명 상태 (81 플래그)
거실등1.register_status("81", "power", "state_topic", r'00(0[01])0[01]0[01]', lambda v: "ON" if v == "01" else "OFF")
거실등2.register_status("81", "power", "state_topic", r'000[01](0[01])0[01]', lambda v: "ON" if v == "01" else "OFF")
간접등.register_status("81", "power", "state_topic", r'000[01]0[01](0[01])0[01]', lambda v: "ON" if v == "01" else "OFF")
주방등.register_status("81", "power", "state_topic", r'000[01]0[01]0[01](0[01])', lambda v: "ON" if v == "01" else "OFF")
식탁등.register_status("81", "power", "state_topic", r'000[01]0[01]0[01]0[01](0[01])', lambda v: "ON" if v == "01" else "OFF")
복도등.register_status("81", "power", "state_topic", r'000[01]0[01]0[01]0[01]0[01](0[01])', lambda v: "ON" if v == "01" else "OFF")
안방등.register_status("81", "power", "state_topic", r'00(0[01])0[01]', lambda v: "ON" if v == "01" else "OFF")
대피공간등.register_status("81", "power", "state_topic", r'000[01](0[01])', lambda v: "ON" if v == "01" else "OFF")

# 개별 조명 상태 (c1 플래그, 중복 보고 대비)
for light in [거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등, 안방등, 대피공간등]:
    light.register_status("c1", "power", "state_topic", r'00(0[01])', lambda v: "ON" if v == "01" else "OFF")

# 개별 조명 제어 명령
for light in [거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등, 안방등, 대피공간등]:
    light.register_command("41", "power", "command_topic", lambda v: "01" if v == "ON" else "00")

# 그룹 상태 계산 함수 (하나라도 켜져있으면 ON)
def group_state(devices):
    return "ON" if any(d.state == "ON" for d in devices) else "OFF"

# 그룹 상태 등록
거실등전체.register_status("81", "power", "state_topic", r'.*', lambda v: group_state([거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등]))
안방등전체.register_status("81", "power", "state_topic", r'.*', lambda v: group_state([안방등, 대피공간등]))

# 그룹 제어 명령 (ON → 모든 자식 켜짐, OFF → 모든 자식 꺼짐)
def group_command(devices, value):
    cmd = "01" if value == "ON" else "00"
    for d in devices:
        d.send_command("power", cmd)
    return cmd

거실등전체.register_command("41", "power", "command_topic", lambda v: group_command([거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등], v))
안방등전체.register_command("41", "power", "command_topic", lambda v: group_command([안방등, 대피공간등], v))


# ==========================================================
# 보일러 (난방)
# ==========================================================

boiler_optional_info = {
    "preset_modes": ["난방", "외출", "온수", "off"],
    "temp_step": 1.0,
    "precision": 1.0,
    "min_temp": 5.0,
    "max_temp": 45.0,
    "send_if_off": "false"
}

# 개별 난방 엔티티
거실난방   = wallpad.add_device("거실 난방",   "36", "11", "climate", optional_info=boiler_optional_info)
안방난방   = wallpad.add_device("안방 난방",   "36", "12", "climate", optional_info=boiler_optional_info)
확장난방   = wallpad.add_device("확장 난방",   "36", "13", "climate", optional_info=boiler_optional_info)
제인이방난방 = wallpad.add_device("제인이방 난방", "36", "14", "climate", optional_info=boiler_optional_info)
팬트리난방 = wallpad.add_device("팬트리 난방", "36", "15", "climate", optional_info=boiler_optional_info)

# 그룹 난방 엔티티
난방전체 = wallpad.add_device(
    device_name="난방 전체",
    device_id="36",
    device_subid="1f",
    device_class="climate",
    child_device=[거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방]
)

# 그룹 가용성 상태
난방전체.register_status("01", "availability", "availability_topic", r'()', lambda v: "online")

# ----------------------------------------------------------
# 상태 보고 (81 응답 패킷)
# ----------------------------------------------------------
# 모드 플래그 cc dd ee ff → 난방, 외출, 예약, 온수
# 비트마스크: 1=조절기1, 2=조절기2, 4=조절기3, 8=조절기4, 16=조절기5

def parse_mode(value, bit_index, label):
    return label if (int(value, 16) >> bit_index) & 1 else "off"

# 난방 모드
거실난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'..(..)..............',
    lambda v: parse_mode(v, 0, "난방"))
안방난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'..(..)..............',
    lambda v: parse_mode(v, 1, "난방"))
확장난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'..(..)..............',
    lambda v: parse_mode(v, 2, "난방"))
제인이방난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'..(..)..............',
    lambda v: parse_mode(v, 3, "난방"))
팬트리난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'..(..)..............',
    lambda v: parse_mode(v, 4, "난방"))

# 외출 모드
거실난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'....(..)............',
    lambda v: "외출" if int(v,16)&1 else "off")
# 동일하게 안방/확장/제인이방/팬트리 난방에 적용 가능

# 온수 모드
거실난방.register_status("81", "preset_mode", "preset_mode_state_topic", r'........(..)........',
    lambda v: "온수" if int(v,16)&1 else "off")
# 동일하게 각 방에 적용

# 목표온도 / 현재온도
거실난방.register_status("81", "temperature", "temperature_state_topic", r'........(..)........',
    lambda v: int(v,16)%128 + int(v,16)//128*0.5)
거실난방.register_status("81", "current_temperature", "current_temperature_topic", r'..........(..)......',
    lambda v: int(v,16)%128 + int(v,16)//128*0.5)
# 동일하게 안방/확장/제인이방/팬트리 난방에 적용

# ----------------------------------------------------------
# 제어 명령
# ----------------------------------------------------------
# 그룹 제어
난방전체.register_command("43", "preset_mode", "preset_mode_command_topic",
    lambda v: {"난방":"01","외출":"02","온수":"03","off":"00"}[v])

# 개별 제어
for room in [거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방]:
    room.register_command("43", "preset_mode", "preset_mode_command_topic",
        lambda v: {"난방":"01","외출":"02","온수":"03","off":"00"}[v])
    room.register_command("44", "temperature", "temperature_command_topic",
        lambda v: format(int(float(v)//1 + float(v)%1*128*2), '02x'))

wallpad.loop()
