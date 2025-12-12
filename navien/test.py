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
    def __init__(self, device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.__message_flag = {}            # {'power': '41'}
        self.__command_process_func = {}

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name = None, process_func = lambda v: v):
        device_name = self.device_name if device_name == None else device_name
        self.__status_messages_map[message_flag].append({'regex': regex, 'process_func': process_func, 'device_name': device_name, 'attr_name': attr_name, 'topic_class': topic_class})

    def register_command(self, message_flag, attr_name, topic_class, process_func = lambda v: v):
        self.__command_messages_map[attr_name] = {'message_flag': message_flag, 'attr_name': attr_name, 'topic_class': topic_class, 'process_func': process_func}

    def parse_payload(self, payload_dict):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['message_flag']]:
                topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                result[topic] = status['process_func'](re.match(status['regex'], payload_dict['data'])[1])
        return result

    def get_command_payload_byte(self, attr_name, attr_value):  # command('power', 'ON')   command('percentage', 'middle')
        attr_value = self.__command_messages_map[attr_name]['process_func'](attr_value)

        command_payload = ['f7', self.device_id, self.device_subid, self.__command_messages_map[attr_name]['message_flag'], '01', attr_value]
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        return bytearray.fromhex(' '.join(command_payload))

    def get_mqtt_discovery_payload(self):
        result = {
            '~': '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            'name': self.device_name,
            'uniq_id': self.device_unique_id,
        }
        result.update(self.optional_info)
        for status_list in self.__status_messages_map.values():
            for status in status_list:
                result[status['topic_class']] = '/'.join(['~', status['attr_name']])

        for status_list in self.__command_messages_map.values():
            result[status_list['topic_class']] = '/'.join(['~', status_list['attr_name'], 'set'])

        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii = False)

    def get_status_attr_list(self):
        return list(set([status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]))

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client(client_id="rs485_2mqtt", protocol=mqtt.MQTTv311)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, MQTT_PORT)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print("✅ MQTT 연결 성공")
            self.register_mqtt_discovery()
        else:
            print("❌ MQTT 연결 실패, 코드:", rc)

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
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
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
