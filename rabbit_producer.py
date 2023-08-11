import pika, json, sys, os

class RMQproducer:
    def __init__(self, routingKey, config):

        self.config = config
        self.routingKey = routingKey
        self.exchange = self.config["exchange"]
        self.connection = self._create_connection()

    def _create_connection(self):

        credentials = pika.PlainCredentials(self.config['login'], self.config['password'])
        parameters = pika.ConnectionParameters(host=self.config['host'],
                        port=self.config['port'],
                        virtual_host='/',
                        credentials=credentials)
        connection = pika.BlockingConnection(parameters)
        return connection

    def send_message(self, message):

        channel = self.connection.channel()

        channel.queue_declare(queue=self.routingKey)

        channel.basic_publish(exchange=self.exchange,
                            routing_key=self.routingKey,
                            body=json.dumps(message))

        self.connection.close()

        print(" [x] Sent %r" % message)

# Doc: https://www.rabbitmq.com/tutorials/tutorial-five-python.html

#queueName = 'IROQueue'
routingKey = 'reports'
notification_producer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : 'tasks',
                                'login':'tubs',
                                'password':'sbut'}

# https://github.com/H2020-FISHY/IRO/blob/main/iro/sending.py

if __name__ == '__main__':

    try:

        init_rabbit = RMQproducer(routingKey, notification_producer_config)
        message = {"test": "test"}
        init_rabbit.send_message(message)

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
