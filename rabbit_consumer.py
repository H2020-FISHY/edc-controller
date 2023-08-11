import pika, sys, os
import json, base64
from xml.dom import minidom
import requests
from datetime import datetime
from rabbit_producer import RMQproducer

def lowerCaseXMLTags(xml_string):

        # parse the xml string
        dom = minidom.parseString(xml_string)

        # iterate through all elements in the xml
        for node in dom.getElementsByTagName("*"):
            # change the first letter of the tag name to lowercase
            node.tagName = node.tagName[0].lower() + node.tagName[1:]

        # return the modified xml as a string
        return dom.toxml()

class RMQsubscriber:

    def __init__(self, queueName, bindingKey, config):

      self.queueName = queueName
      self.bindingKey = bindingKey
      self.config = config
      self.connection = self._create_connection()

    def __del__(self):
        if self.connection.is_open:
            self.connection.close()

    def _create_connection(self):

        credentials = pika.PlainCredentials(self.config['login'], self.config['password'])
        parameters = pika.ConnectionParameters(host=self.config['host'],
                          port=self.config['port'],
                          virtual_host='/',
                          credentials=credentials)
        connection = pika.BlockingConnection(parameters)

        return connection

    def on_message_callback(self, channel, method, properties, body):

        print(" [x] Received %r" % body)

        hspl_filename = "fishy_hspl.xml"

        message = json.loads(body.decode('utf-8'))

        if message["task_type"] != "policies.create":
            print("Ignoring message of type: " + message["task_type"])
            return

        message = message["details"]
        policy_id_cr = message["id"]

        message_data = json.loads(message["HSPL"].encode('utf-8'))
        if message_data["mode"] == "standalone":
            print("Ignoring standalone notification")
            return

        base64_hspl_string: str = message_data["payload"]

        hspl = base64.b64decode(base64_hspl_string.encode("utf-8")).decode('utf-8')

        with open(hspl_filename, 'w') as file:
            # Write the string to the file
            file.write(hspl)

        cookies = {"policy_filename": hspl_filename}

        #Upload HSPL

        url = f"http://localhost:5000/upload_hspl"
        file = {"file": open(hspl_filename, "rb")}
        response = requests.post(url, files=file)
        #print(response.text)

        # Get NSFs configurations

        url = f"http://localhost:5000/refinement_no_gui"
        response = requests.get(url, cookies=cookies)
        #print(response.text)

        # Execute refinement

        url = f"http://localhost:5000/refinement_no_gui"
        data = {"hspl1": ["firewall-1"]} # what about {"hspl1": ["firewall-HP", "firewall-1"]}?
        response = requests.post(url, cookies=cookies, json=data)
        #print(response.text)
        # Response example:
        # {"fishy_hspl_1666080055":["firewall-HP_IpTables_RuleInstance.xml","firewall-1_IpTables_RuleInstance.xml"]}

        url = f"http://localhost:5000/result"
        nsf_confs = json.loads(response.text)
        index = 1

        low_level_rules = []
        for key, value in nsf_confs.items():
            for nsf_conf in value:

                request_url = f"{url}/{key}/{nsf_conf}"
                #print(request_url)
                response = requests.get(request_url)

                # The XML file received must pass through the lowerCaseXMLTags function because
                # the security capability model doesn't recognize XML tags if the first
                # letter is uppercase. The refinement engine produces XML policies
                # in which the first letter is upper case, hence this step is needed.
                xml_string = lowerCaseXMLTags(response.text)
                xml = minidom.parseString(xml_string)
                prettyxml_string = xml.toprettyxml()
                # print(prettyxml)

                ### Push to Central Repository

                url = "https://" + "fishy.xlab.si/tar/api/mspl"

                headers = {'Content-Type': 'application/json'}

                # Get the current UTC time
                now_utc = datetime.utcnow()
                # Format the time as a string in ISO 8601 format with milliseconds and a 'Z' suffix
                time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                base64_mlsp_string = base64.b64encode(prettyxml_string.encode('utf-8')).decode('utf-8')

                data = {"payload": base64_mlsp_string, "mode": "asynchronous"}

                message = {"source": "edc-refeng", "data": json.dumps(data), "status": "both", "timestamp": time_str, "policy_id": policy_id_cr}

                raw_response = requests.post(url, headers=headers, data=json.dumps(message))
                response = json.loads(raw_response.text)

                if raw_response.status_code == 201:
                    response_data = raw_response.json()
                    print("MSPL loaded on CR!")
                    print(response_data)
                else:
                    print("Error:", raw_response.status_code)


                ### Directly producing on RabbitMQ
                # # queueName = 'IROQueue'
                # routingKey = 'mlsp'
                # notification_producer_config = {'host': 'fishymq.xlab.si',
                #                                 'port': 45672,
                #                                 'exchange' : 'tasks',
                #                                 'login':'tubs',
                #                                 'password':'sbut'}

                # init_rabbit = RMQproducer(routingKey, notification_producer_config)
                # base64_mlsp_string = base64.b64encode(prettyxml_string.encode('utf-8')).decode('utf-8')
                # message = {"mlsp": base64_mlsp_string}
                # init_rabbit.send_message(message)

        channel.basic_ack(delivery_tag=method.delivery_tag)

    def setup(self):

        channel = self.connection.channel()

        # This method creates or checks a queue
        channel.queue_declare(queue=self.queueName)

        # Binds the queue to the specified exchange
        channel.queue_bind(queue=self.queueName,
                        exchange=self.config['exchange'],
                        routing_key=self.bindingKey)

        channel.basic_consume(queue=self.queueName,
                            on_message_callback=self.on_message_callback,
                            auto_ack=False)

        print('[*] Waiting for data for ' + self.queueName + '. To exit press CTRL+C')

        try:

            channel.start_consuming()

        except KeyboardInterrupt:

            channel.stop_consuming()


queueName = 'refeng'
key = 'policies.create'
notification_consumer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : 'tasks',
                                'login':'tubs',
                                'password':'sbut'}

if __name__ == '__main__':

    try:

       init_rabbit = RMQsubscriber(queueName, key, notification_consumer_config)
       init_rabbit.setup()

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)