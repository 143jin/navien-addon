import paho.mqtt.client as mqtt
import re
import json   # ← 이 줄 추가
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict
# 1. 애드온 설정 불러오기
def load_config():
    with open('/data/options.json') as f:
        return json.load(f)

config = load_config()
MQTT_SERVER = config["MQTT"]["server"]
MQTT_PORT = int(config["MQTT"]["port"])
MQTT_USERNAME = config["MQTT"]["username"]
MQTT_PASSWORD = config["MQTT"]["password"]
ROOT_TOPIC_NAME = 'rs485_2mqtt'
MQTT_COMMAND_TOPIC = "rs485_2mqtt/dev/command"
MQTT_RAW_TOPIC = "rs485_2mqtt/dev/raw"
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

class Device:
    def __init__(self, device_name, device_id, device_subid, device_class,
                 child_device=None, mqtt_discovery=None, optional_info=None):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_class = device_class
        self.device_unique_id = f"rs485_{device_id}_{device_subid}"
        self.__status_messages_map = {}
        self.__command_messages_map = {}
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info or {}

    # 상태 등록
    def register_status(self, message_flag, attr_name, topic_class, regex, process_func):
        if message_flag not in self.__status_messages_map:
            self.__status_messages_map[message_flag] = []
        self.__status_messages_map[message_flag].append({
            'attr_name': attr_name,
            'topic_class': topic_class,
            'regex': regex,
            'process_func': process_func
        })

    # 명령 등록
    def register_command(self, message_flag, attr_name, topic_class, process_func):
        if message_flag not in self.__command_messages_map:
            self.__command_messages_map[message_flag] = []
        self.__command_messages_map[message_flag].append({
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        })

    # 상태 속성 목록 반환 (에러 해결 포인트)
    def get_status_attr_list(self):
        return list(set(
            status['attr_name']
            for status_list in self.__status_messages_map.values()
            for status in status_list
        ))

    # 명령 페이로드 생성
    def get_command_payload_byte(self, attr_name, value):
        for message_flag, command_list in self.__command_messages_map.items():
            for command in command_list:
                if command['attr_name'] == attr_name:
                    payload = command['process_func'](value)
                    return message_flag, payload
        return None, None

    # MQTT Discovery 메시지 생성
    def get_mqtt_discovery_payload(self):
        result = {
            "~": '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            "name": self.device_name,
            "unique_id": self.device_unique_id,
            "availability_topic": "~/availability",
            "state_topic": "~/power",
            "command_topic": "~/power/set",
            "preset_mode_state_topic": "~/preset_mode",
            "preset_mode_command_topic": "~/preset_mode/set",
            "device": {
                "identifiers": [self.device_unique_id],
                "name": self.device_name
            }
        }
        # optional_info 병합
        result.update(self.optional_info)
        return json_dumps(result, ensure_ascii=False)
    def get_status_attr_list(self):
        """등록된 상태 메시지들의 attr_name 목록을 반환"""
        return list(set(
            status['attr_name']
            for status_list in self.__status_messages_map.values()
            for status in status_list
        ))

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client(client_id="rs485_2mqtt", protocol=mqtt.MQTTv5)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, MQTT_PORT)

    def on_connect(self, client, userdata, flags, reasonCode, properties):
        print("Connected with result code", reasonCode)
        if reasonCode == 0:   # ✅ rc 대신 reasonCode 사용
            print("MQTT connection successful")
        else:
            print("MQTT connection failed:", reasonCode)

    def listen(self):
        # raw + command 토픽 구독
        self.mqtt_client.subscribe(
            [(topic, 1) for topic in [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()]
        )
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos=1, retain=True)

    # ... 나머지 add_device, get_device, get_topic_list_to_listen, xor, add 그대로 유지 ...
    def add_device(self, device_name, device_id, device_subid, device_class, child_device = [], mqtt_discovery = True, optional_info = {}):
        device = Device(device_name, device_id, device_subid, device_class, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [device for device in self._device_list if device.device_name == kwargs['device_name']][0]
        else:
            return [device for device in self._device_list if device.device_id == kwargs['device_id'] and device.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        return ['/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set']) for device in self._device_list for attr_name in device.get_status_attr_list()]

    @classmethod
    def xor(cls, hexstring_array):
        return format(reduce((lambda x, y: x^y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')

    @classmethod
    def add(cls, hexstring_array): # hexstring_array ['f7', '32', ...]
        return format(reduce((lambda x, y: x+y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        payload_hexstring_array = [payload_hexstring[i:i+2] for i in range(0, len(payload_hexstring), 2)] # ['f7', '0e', '1f', '81', '04', '00', '00', '00', '00', '63', '0c']
        try:
            result = int(payload_hexstring_array[4], 16) + 7 == len(payload_hexstring_array) and cls.xor(payload_hexstring_array[:-2]) == payload_hexstring_array[-2:-1][0] and cls.add(payload_hexstring_array[:-1]) == payload_hexstring_array[-1:][0]
            return result
        except:
            return False

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw': # ew11이 MQTT에 rs485 패킷을 publish하는 경우
            for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]: # payload 내에 여러 메시지가 있는 경우, \f7 disappear as delimiter here
                payload_hexstring = 'f7' + payload_raw_bytes.hex() # 'f7361f810f000001000017179817981717969896de22'
                try:
                    if self.is_valid(payload_hexstring):
                        payload_dict = re.match(r'f7(?P<device_id>0e|12|32|33|36)(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})', payload_hexstring).groupdict()

                        for topic, value in self.get_device(device_id = payload_dict['device_id'], device_subid = payload_dict['device_subid']).parse_payload(payload_dict).items():
                            client.publish(topic, value, qos = 1, retain = False)
                    else:
                        continue
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos = 1, retain = True)

        else: # homeassistant에서 명령하여 MQTT topic을 publish하는 경우
            topic_split = msg.topic.split('/') # rs485_2mqtt/light/안방등/power/set
            device = self.get_device(device_name = topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos = 2, retain = False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# 프리셋 모드 매핑 (RS485 패킷 ↔ 프리셋 문자열)
packet_2_preset = {
    "01": "바이패스",
    "03": "전열",
    "04": "오토",
    "05": "공기청정",
    "00": "off"
}
preset_2_packet = {v: k for k, v in packet_2_preset.items()}


optional_info = {
    'optimistic': 'false',
    'preset_modes': ['off', '바이패스', '전열', '오토', '공기청정']
}
# Wallpad 인스턴스 생성
wallpad = Wallpad()

# 환풍기 등록
환풍기 = wallpad.add_device(
    device_name='환풍기',
    device_id='32',
    device_subid='01',
    device_class='fan',
    optional_info=optional_info
)


# 상태 등록
환풍기.register_status(
    message_flag='01',
    attr_name='availability',
    topic_class='availability_topic',
    regex=r'()',
    process_func=lambda v: 'online'
)

환풍기.register_status(
    message_flag='81',
    attr_name='power',
    topic_class='state_topic',
    regex=r'00(0[01])0[0-3]0[013]00',
    process_func=lambda v: 'ON' if v == '01' else 'OFF'
)

환풍기.register_status(
    message_flag='c1',
    attr_name='power',
    topic_class='state_topic',
    regex=r'00(0[01])0[0-3]0[013]00',
    process_func=lambda v: 'ON' if v == '01' else 'OFF'
)

# 프리셋 모드 상태 (패킷 → 프리셋 변환)
환풍기.register_status(
    message_flag='81',
    attr_name='preset_mode',
    topic_class='preset_mode_state_topic',
    regex=r'000[01](0[0-5])0[013]00',
    process_func=lambda v: packet_2_preset[v]
)

환풍기.register_status(
    message_flag='c2',
    attr_name='preset_mode',
    topic_class='preset_mode_state_topic',
    regex=r'000[01](0[0-5])0[013]00',
    process_func=lambda v: packet_2_preset[v]
)

# 명령 등록
환풍기.register_command(
    message_flag='41',
    attr_name='power',
    topic_class='command_topic',
    process_func=lambda v: '01' if v == 'ON' else '00'
)

환풍기.register_command(
    message_flag='43',
    attr_name='preset_mode',
    topic_class='preset_mode_command_topic',
    process_func=lambda v: preset_2_packet[v]
)

#실행 시작
wallpad.listen()
