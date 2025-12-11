import os
import json
import re
import paho.mqtt.client as mqtt
import serial
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

MQTT_COMMAND_TOPIC = "rs485_2mqtt/dev/command"
MQTT_RAW_TOPIC = "rs485_2mqtt/dev/raw"

# 2. 환풍기 Discovery 메시지 발행
def publish_fan_discovery(client):
    discovery_topic = "homeassistant/fan/navien_fan/config"
    payload = {
        "name": "Navien Fan",
        "unique_id": "navien_fan_1",
        "state_topic": MQTT_RAW_TOPIC,
        "command_topic": MQTT_COMMAND_TOPIC,
        "device": {
            "identifiers": ["navien_fan"],
            "name": "Navien RS485 Fan",
            "manufacturer": "Navien"
        }
    }
    client.publish(discovery_topic, json.dumps(payload), retain=True)
    print("Published fan discovery config")

# 3. MQTT 콜백
def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT broker with result code " + str(rc))
    client.subscribe(MQTT_COMMAND_TOPIC)
    publish_fan_discovery(client)

def on_message(client, userdata, msg):
    print(f"Received message on {msg.topic}: {msg.payload.decode()}")
    # TODO: RS485 전송 로직 추가 (환풍기 제어)

# 4. Device 클래스 (확장용)
class Device:
    def __init__(self, device_name, device_id, device_subid, device_class,
                 child_device=None, mqtt_discovery=True, optional_info=None):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = f"rs485_{device_id}_{device_subid}"
        self.device_class = device_class
        self.child_device = child_device or []
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info or {}

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class,
                        device_name=None, process_func=lambda v: v):
        device_name = self.device_name if device_name is None else device_name
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': device_name,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def register_command(self, message_flag, attr_name, topic_class,
                         process_func=lambda v: v):
        self.__command_messages_map[attr_name] = {
            'message_flag': message_flag,
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        }

    def parse_payload(self, payload_dict, root_topic):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['message_flag']]:
                topic = '/'.join([root_topic, device.device_class,
                                  device.device_name, status['attr_name']])
                result[topic] = status['process_func'](
                    re.match(status['regex'], payload_dict['data'])[1]
                )
        return result

    def get_mqtt_discovery_payload(self, root_topic, ha_root_topic):
        result = {
            '~': '/'.join([root_topic, self.device_class, self.device_name]),
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
        return json.dumps(result, ensure_ascii=False)

# 5. Wallpad 클래스 (RS485 ↔ MQTT 브리지)
class Wallpad:
    _device_list = []

    def __init__(self, config):
        self.config = config
        self.root_topic = "rs485_2mqtt"
        self.ha_root_topic = "homeassistant"

        self.mqtt_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(
            username=config["MQTT"]["username"],
            password=config["MQTT"]["password"]
        )
        self.mqtt_client.connect(config["MQTT"]["server"], config["MQTT"]["port"])

    def on_raw_message(self, client, userdata, msg):
        print(f"RS485 raw message: {msg.payload.decode()}")
        # TODO: RS485 데이터 파싱 후 MQTT 발행

    def on_disconnect(self, client, userdata, rc):
        print("MQTT disconnected")

# 6. 메인 실행
def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_SERVER, MQTT_PORT, 60)
    client.loop_forever()

if __name__ == "__main__":
    main()
# 2. Device 클래스
class Device:
    def __init__(self, device_name, device_id, device_subid, device_class,
                 child_device=None, mqtt_discovery=True, optional_info=None):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = f"rs485_{device_id}_{device_subid}"
        self.device_class = device_class
        self.child_device = child_device or []
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info or {}

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class,
                        device_name=None, process_func=lambda v: v):
        device_name = self.device_name if device_name is None else device_name
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': device_name,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def register_command(self, message_flag, attr_name, topic_class,
                         process_func=lambda v: v):
        self.__command_messages_map[attr_name] = {
            'message_flag': message_flag,
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        }

    def parse_payload(self, payload_dict, root_topic):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['message_flag']]:
                topic = '/'.join([root_topic, device.device_class,
                                  device.device_name, status['attr_name']])
                result[topic] = status['process_func'](
                    re.match(status['regex'], payload_dict['data'])[1]
                )
        return result

    def get_command_payload_byte(self, attr_name, attr_value):
        attr_value = self.__command_messages_map[attr_name]['process_func'](attr_value)
        command_payload = ['f7', self.device_id, self.device_subid,
                           self.__command_messages_map[attr_name]['message_flag'],
                           '01', attr_value]
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        return bytearray.fromhex(' '.join(command_payload))

    def get_mqtt_discovery_payload(self, root_topic, ha_root_topic):
        result = {
            '~': '/'.join([root_topic, self.device_class, self.device_name]),
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
        return json.dumps(result, ensure_ascii=False)

    def get_status_attr_list(self):
        return list(set([status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]))

# 3. Wallpad 클래스
class Wallpad:
    _device_list = []

    def __init__(self, config):
        self.config = config
        self.root_topic = "rs485_2mqtt"
        self.ha_root_topic = "homeassistant"

        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(
            username=config["MQTT"]["username"],
            password=config["MQTT"]["password"]
        )
        self.mqtt_client.connect(config["MQTT"]["server"], config["MQTT"]["port"])

    def listen(self):
        self.register_mqtt_discovery()
        topics = [self.root_topic + '/dev/raw'] + self.get_topic_list_to_listen()
        self.mqtt_client.subscribe([(topic, 2) for topic in topics])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([self.ha_root_topic, device.device_class,
                                  device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload(self.root_topic, self.ha_root_topic)
                self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class,
                   child_device=None, mqtt_discovery=True, optional_info=None):
        device = Device(device_name, device_id, device_subid, device_class,
                        child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        # 기본 availability 등록
        device.register_status("01", "availability", r"()", "availability_topic",
                               process_func=lambda v: "online")
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [d for d in self._device_list if d.device_name == kwargs['device_name']][0]
        else:
            return [d for d in self._device_list if d.device_id == kwargs['device_id']
                    and d.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        return ['/'.join([self.root_topic, d.device_class, d.device_name, attr, 'set'])
                for d in self._device_list for attr in d.get_status_attr_list()]

    @classmethod
    def xor(cls, hexstring_array):
        return format(reduce(lambda x, y: x ^ y, [int(x, 16) for x in hexstring_array]), '02x')

    @classmethod
    def add(cls, hexstring_array):
        return format(reduce(lambda x, y: x + y, [int(x, 16) for x in hexstring_array]), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        arr = [payload_hexstring[i:i+2] for i in range(0, len(payload_hexstring), 2)]
        try:
            return (int(arr[4], 16) + 7 == len(arr)
                    and cls.xor(arr[:-2]) == arr[-2]
                    and cls.add(arr[:-1]) == arr[-1])
        except:
            return False

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == self.root_topic + '/dev/raw':
            for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]:
                payload_hexstring = 'f7' + payload_raw_bytes.hex()
                try:
                    if self.is_valid(payload_hexstring):
                        payload_dict = re.match(
                            r'f7(?P<device_id>[0-9a-f]{2})(?P<device_subid>[0-9a-f]{2})'
                            r'(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)'
                            r'(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})',
                            payload_hexstring).groupdict()
                        device = self.get_device(device_id=payload_dict['device_id'],
                                                 device_subid=payload_dict['device_subid'])
                        for topic, value in device.parse_payload(payload_dict, self.root_topic).items():
                            client.publish(topic, value, qos=1, retain=False)
                except Exception as e:
                    client.publish(self.root_topic + '/dev/error', str(e), qos=1, retain=True)
        else:
            topic_split = msg.topic.split('/')
            device = self.get_device(device_name=topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(self.root_topic + '/dev/command', payload, qos=2, retain=False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# 4. 메인 실행
if __name__ == "__main__":
    config = load_config()
    wallpad = Wallpad(config)

# 환풍기 프리셋 매핑
packet_2_preset = {
    "01": "바이패스",
    "03": "전열",
    "04": "오토",
    "05": "공기청정",
    "00": "off"
}
preset_2_packet = {v: k for k, v in packet_2_preset.items()}

# 환풍기 속도 매핑
packet_2_speed = {
    "01": "약",   # 33%
    "02": "중",   # 66%
    "03": "강"    # 100%
}
speed_2_packet = {v: k for k, v in packet_2_speed.items()}

optional_info = {
    "optimistic": "false",
    "preset_modes": ["off", "바이패스", "전열", "오토", "공기청정"],
    "supported_speeds": ["약", "중", "강"]
}

fan = wallpad.add_device(
    device_name="환풍기",
    device_id="32",
    device_subid="01",
    device_class="fan",
    optional_info=optional_info
)

# 상태 등록 (모드)
fan.register_status(
    message_flag="81",
    attr_name="preset_mode",
    topic_class="preset_mode_state_topic",
    regex=r"05.{4}(0[0-5])",
    process_func=lambda v: packet_2_preset[v]
)

# 명령 등록 (모드)
fan.register_command(
    message_flag="43",
    attr_name="preset_mode",
    topic_class="preset_mode_command_topic",
    process_func=lambda v: preset_2_packet[v]
)

# OFF 명령
fan.register_command(
    message_flag="41",
    attr_name="power",
    topic_class="command_topic",
    process_func=lambda v: "00" if v == "off" else "01"
)

# 상태 등록 (속도)
fan.register_status(
    message_flag="81",
    attr_name="speed",
    topic_class="percentage_state_topic",
    regex=r"05.{4}0[0-5].{2}(0[1-3])",
    process_func=lambda v: packet_2_speed[v]
)

# 명령 등록 (속도)
fan.register_command(
    message_flag="42",
    attr_name="speed",
    topic_class="percentage_command_topic",
    process_func=lambda v: speed_2_packet[v]
)
