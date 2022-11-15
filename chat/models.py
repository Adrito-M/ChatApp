from django.db import models
import time

def timestamp():
    return time.time_ns() // 10**6

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    passwordHash = models.CharField(max_length=64)
    salt = models.CharField(max_length=64)
    pvtkeyhash = models.CharField(max_length=64, default=None)
    aesciphertext = models.TextField(max_length=1500)
    aesnonce = models.CharField(max_length=100)
    aestag = models.CharField(max_length=100)
    gpowerkey = models.TextField(max_length=650)


class Message(models.Model):
    content = models.TextField(max_length=2000)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent', default=None)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received', default=None)
    status = models.CharField(max_length=1, choices=(
        ('S', 'Sent'),
        ('R', 'Received'),
        ('D', 'Seen')
    ), default='S')
    time = models.BigIntegerField(default=timestamp)
