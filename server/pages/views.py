from django.http import HttpResponse, HttpResponseNotAllowed
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Account


@login_required
def confirmView(request):

	# FLAW 1:
	# A04:2021 Insecure Design: The money transfer does not include any business logic
	# validation, such as preventing negative amounts, ensuring sufficient balance or
	# blocking self-transfers.
	
	# FLAW 2:
	# A05:2021 Security Misconfiguration (csrf): The confirmation endpoint is not
	# protected with CSRF tokens, allowing an attacker to trick the user into making an unintended transfer.

	# FLAW 3:
	# A08:2021 Software and Data Integrity Failures: The transaction logic blindly
	# updates account balances without safeguards, which makes it possible to corrupt
	# the integrity of financial data.

	# BAD:
	amount = int(request.GET.get('amount'))
	to = User.objects.get(username=request.GET.get('to'))
	request.user.account.balance -= amount
	to.account.balance += amount
	request.user.account.save()
	to.account.save()
	return redirect('/')

    # FIX (commented):
    # if request.method != "POST":
    #     return HttpResponseNotAllowed(['POST'])
    # try:
    #     amount = int(request.session['amount'])
    #     if amount <= 0:
    #         raise ValueError("Et voi siirtää negatiivista tai nolla summaa!")
    #     to = User.objects.get(username=request.session['to'])
    #     if to == request.user:
    #         raise ValueError("Yritit huiputaa. Et voi siirtää itsellesi.")
    #     if request.user.account.balance < amount:
    #         raise ValueError("Ei ole massia tarpeeksi!")
    #     request.user.account.balance -= amount
    #     to.account.balance += amount
    #     request.user.account.save()
    #     to.account.save()
    # except Exception as e:
    #     return HttpResponse("Ei onnistunu: " + str(e))
    # return redirect('/')

@login_required
def transferView(request):

	# FLAW 4:
	# A03:2021 Injection: User input (to, amount) is taken directly from request.GET/POST
	# and stored in the session without validation. This allows for type confusion
	# and potential DoS attacks.

	# BAD:
	request.session['to'] = request.POST.get('to')
	request.session['amount'] = request.POST.get('amount')
	return render(request, 'pages/confirm.html')

	# FIX (commented):
    # if request.method == "POST":
    #     to = request.POST.get('to')
    #     amount = request.POST.get('amount')
    #     try:
    #         amount = int(amount)
    #         if amount <= 0:
    #             raise ValueError("Mene töihin. Ei sulle ole massia, köyhä.")
    #         User.objects.get(username=to)
    #         request.session['to'] = to
    #         request.session['amount'] = amount
    #     except (ValueError, User.DoesNotExist):
    #         return HttpResponse("Et voi siirtää negatiivista rahamäärää uuno!", status=400)
    #     return render(request, 'pages/confirm.html')
    # else:
    #     return redirect('/')

@login_required
def homePageView(request):
	accounts = Account.objects.exclude(user_id=request.user.id)
	return render(request, 'pages/index.html', {'accounts': accounts})
