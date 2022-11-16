from channels.generic.websocket import JsonWebsocketConsumer
from asgiref.sync import async_to_sync
from . import auth, message
import channels.layers

channel_layer = channels.layers.get_channel_layer()

class UserChatConsumer(JsonWebsocketConsumer):

    channel_dict = dict()

    def connect(self):
        self.accept()
    
    def receive_json(self, content, **kwargs):
        if 'jwt' not in list(content.keys()):
            self.close()
            return

        if type(content['jwt']) is not str:
            self.close()
            return
            
        ok, dic = auth.verifyJWT(content['jwt'])
        if not ok:
            self.close()
            return
        
        if content['purpose'] == 'connect':
            async_to_sync(self.channel_layer.group_add)(dic['username'], self.channel_name)
            self.channel_dict[self.channel_name] = dic['username']
            self.send_json({
                'purpose': 'connect',
                'status': 'success'
            })
            return

        elif content['purpose'] == 'get':
            return            

        elif content['purpose'] == 'send':
            receiver = content['receiver']
            sender = dic['username']
            messageContent = content['content']
            message.addMessage(messageContent, sender, receiver)
            async_to_sync(self.channel_layer.group_send)(receiver, {
                'type': 'chat.message',
                'purpose': 'incoming',
                'sender': sender,
                'content': messageContent,
            })
            self.send_json({
                'purpose': 'send',
                'status': 'success',
            })
            return
        
        elif content['purpose'] == 'receive':
            receiver = dic['username']
            broadcasts = message.receiveMessage(receiver)
            for broadcast in broadcasts:
                async_to_sync(self.channel_layer.group_send)(broadcast, {
                    'type': 'chat.message',
                    'purpose': 'receive',
                    'receiver': receiver
                })
            return

        elif content['purpose'] == 'seen':
            receiver = dic['username']
            sender = content['sender']
            message.seenMessage(receiver, sender)
            async_to_sync(self.channel_layer.group_send)(sender, {
                'type': 'chat.message',
                'purpose': 'seen',
                'receiver': receiver
            })
            return



    def disconnect(self, code):
        try:
            async_to_sync(self.channel_layer.group_discard)(self.channel_dict[self.channel_name], self.channel_name)
            del self.channel_dict[self.channel_name]
        except KeyError:
            pass

    def chat_message(self, event):
        self.send_json(event)