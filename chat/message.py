from chat.models import User, Message
from typing import List
from collections import OrderedDict

def addMessage(content: str, senderName: str, receiverName: str) -> None:
    try:
        sender = User.objects.get(username=senderName)
        receiver = User.objects.get(username=receiverName)
    except Message.DoesNotExist:
        return
    message = Message(
        content = content,
        sender = sender,
        receiver = receiver,
        status = 'S'
    )
    message.save()

def receiveMessage(receiverName: str) -> List[str]:
    try:
        receiver = User.objects.get(username=receiverName)
    except Message.DoesNotExist:
        return
    
    messages = Message.objects.filter(receiver=receiver, status='S')
    
    broadcast = []

    for message in messages:
        broadcast.append(message.sender)

    messages.update(status='R')


def seeMessage(receiverName: str, senderName: str) -> None:
    try:
        receiver = User.objects.get(username=receiverName)
        sender = User.objects.get(username=senderName)
    except Message.DoesNotExist:
        return
    
    messages = Message.objects.filter(
        receiver=receiver,
        sender=sender,
        status='S'
        ) | Message.objects.filter(
            receiver=receiver,
            sender=sender,status='R'
        )

    messages.update(status='D')

def getMessage(username: str) -> dict:
    user = User.objects.get(username=username)
    messages = Message.objects.filter(receiver=user) | Message.objects.filter(sender=user)
    messages.order_by('time')
    inbox = dict()
    for message in messages:
        if message.sender == user:
            inbox[message.receiver.username] = []
        elif message.receiver == user:
            inbox[message.sender.username] = []
    for message in messages:
        if message.sender == user:
            inbox[message.receiver.username].append({
                'type': 'sent',
                'content': message.content,
                'username': message.receiver.username,
                'name': message.receiver.name,
                'gpowerkey': message.receiver.gpowerkey,
                'time': message.time,
                'status': message.status,
            })
        elif message.receiver == user:
            inbox[message.receiver.username].append({
                'type': 'received',
                'content': message.content,
                'username': message.sender.username,
                'name': message.sender.name,
                'gpowerkey': message.sender.gpowerkey,
                'time': message.time,
                'status': message.status,
            })
    
    sorted_keys = sorted(inbox.keys(), reverse=True, key=lambda x:inbox[x][-1]['time'])

    ordered_inbox = OrderedDict()

    for key in sorted_keys:
        ordered_inbox[key] = inbox[key]

    return ordered_inbox
