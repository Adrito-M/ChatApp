from django.shortcuts import render, redirect
from django.http import JsonResponse,  HttpResponse, HttpResponseForbidden, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from base64 import b64encode
import json
from . import auth, message


# Create your views here.
def index(request):
    return render(request, 'index.html')


def login(request):
    context = {'message':''}
    if request.POST:
        username = request.POST.get('username')
        password = request.POST.get('password')

        if type(username) is not str or type(password) is not str:
            context['message'] = 'Username or Password must be a string'
        elif len(username) == 0:
            context['message'] = 'Username cannot be empty'
        elif len(password) == 0:
            context['message'] = 'Password cannot be empty'
        elif len(username) > 100:
            context['message'] = 'Password cannot be more than 100 characters'
        elif auth.verify(username, password) == -1:
            context['message'] = 'Username does not exist'
        elif auth.verify(username, password) == 0:
            context['message'] = 'Incorrect username or password'
        elif auth.verify(username, password) == 1:
            dic = auth.getUser(username, password)
            jwt = auth.signJWT({'username': dic['username']})
            response = redirect('/dashboard')
            response.set_cookie('jwt', jwt)
            response.set_cookie('info', b64encode(json.dumps(dic).encode()).decode())
            return response
    
    return render(request, 'login.html', context)


def register(request):
    context = {'message':''}
    if request.POST:
        print(request.POST)
        username = request.POST.get('username')
        name = request.POST.get('name')
        password = request.POST.get('password')

        if type(username) is not str or type(password) is not str or type(name) is not str:
            context['message'] = 'Username and Name and Password must be a string'
        elif len(username) == 0:
            context['message'] = 'Username cannot be empty'
        elif len(name) == 0:
            context['message'] = 'Name cannot be empty'
        elif len(password) == 0:
            context['message'] = 'Password cannot be empty'
        else:
            auth.addUser(username, name, password)
            dic = auth.getUser(username, password)
            jwt = auth.signJWT({'username': dic['username']})
            response = redirect('/dashboard')
            response.set_cookie('jwt', jwt)
            response.set_cookie('info', b64encode(json.dumps(dic).encode()).decode())
            return response
            
    return render(request, 'register.html', context)

def dashboard(request):
    isVerified, dic = auth.verifyJWT(request.COOKIES.get('jwt'))
    if not isVerified:
        return redirect('/login', {'message': 'Login Failed'})
    inbox = message.getMessage(dic['username'])
    return render(request, 'dashboard.html', {'inbox':inbox, 'usernames': ' '.join(list(inbox.keys())), 'owner': dic['username'] })


@csrf_exempt
def dfh(request):
    username = request.GET.get('username')
    if type(username) is not str:
        return HttpResponseBadRequest()
    elif auth.validateUsername(username):
        return HttpResponseBadRequest()
    else:
        return JsonResponse({'gpowerkey': str(auth.getgpowerkey(username))})
    
@csrf_exempt
def validateusername(request):
    username = request.GET.get('username')
    if type(username) is not str:
        return HttpResponseBadRequest()
    return JsonResponse({'exists': not auth.validateUsername(username)})
    