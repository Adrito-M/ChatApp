from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async
from . import auth, message

class UserChatConsumer(AsyncJsonWebsocketConsumer):

    channel_dict = dict()

    async def connect(self):
        await self.accept()
    
    async def receive_json(self, content, **kwargs):
        ok, dic = await sync_to_async(auth.verifyJWT)(content.jwt)
        if not ok:
            await self.close()
        
        if content['purpose'] == 'connect':
            await self.channel_layer.group_add(dic['username'], self.channel_name)
            self.channel_dict[self.channel_name] = dic['username']

        elif content['purpose'] == 'get':
            pass

        elif content['purpose'] == 'send':
            receiver = content['receiver']
            sender = dic['username']
            messageContent = content['content']
            await sync_to_async(message.addMessage)(messageContent, sender, receiver)
            await self.channel_layer.group_send(receiver, {
                'type': 'chat.message',
                'purpose': 'send',
                'sender': sender,
                'content': messageContent,
                'gpowerkey': await sync_to_async(auth.getgpowerkey(sender))
            })
            await self.send_json({
                'purpose': 'send',
                'status': 'success',
            })
        
        elif content['purpose'] == 'receive':
            receiver = dic['username']
            broadcasts = await sync_to_async(message.receiveMessage)(receiver)
            for broadcast in broadcasts:
                await self.channel_layer.group_send(broadcast, {
                    'type': 'chat.message',
                    'purpose': 'receive',
                    'receiver': receiver
                })

        elif content['purpose'] == 'seen':
            receiver = dic['username']
            sender = content['sender']
            await sync_to_async(message.seenMessage)(receiver, sender)



    async def disconnect(self, code):
        try:
            await self.channel_layer.group_discard(self.channel_dict[self.channel_name], self.channel_name)
            del self.channel_dict[self.channel_name]
        except KeyError:
            pass
