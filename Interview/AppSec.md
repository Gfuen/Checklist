## How would you implement a secure login field on a high traffic website where performance is a consideration

-TLS is a must to provide confidentiality and integrity
-Input validation to avoid SQLI and XSS
-Single Sigon on systems that are trusted by the community
-Brute force protection (captchas or MFA, time based lock out)
-Password complexity

## What are the various ways to handle account brute forcing

-Account lockouts
-IP restrictions
-Fail2ban
-MFA
-Unique login URLS
-Monitor server logs

## What is Cross Site Rquest Forgery (CSRF)

CSRF is an attack that forces an end user to execute an unwanted actions on a web application in which they're currently authenticated.
With a little help of social engineering an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform site changing requets like transferring finds, chainging their email address, etc...

Conditions
-Relevant action by user
-Cookie session handling
-Attacker can easily determine the values of the request parameters needed to perform action

With these conditions in place, the attacker can construct a web page containing the following HTML:

<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>

## How to Prevent CSRF Attachks

-Include CSRF Toekns within relevant requests
-Use SameSite Cookie Attribute
-Do not use GET requests for state changing operations
-Verify Origin with Standard headers

## If you were a site administrator looking for incoming CSRF attacks, what would you look for?

Did we already implement CSRF tokens?
Did we already have controls in place?

## Whats the difference between HTTP and HTML

HTML - Markup language
HTTP - Networking/Application protocol

## How does HTTP Handle State

Even though multiple requests can be sent over the same HTTP connection the server does not attach any meaning. As far as HTTP is concerned they are all still separate requests and must contain enough information on their own to fulfill the request. That is the essence of "statelessness"

Requests will not be associated with each other absent some shared info the server knows about which is where cookies come in

## Cookie vs Token

Cookie 
- Stateful 
- Session is kept client AND server side
1. Users enters their login credentials
2. Server verifies the credentials and creates session which is stored in a database
3. A cookie with the session ID is placed in the users browser
4. On subsequent requests, the session ID is verified against the database and if valid the request is processed
5. Once a user logs out of the app, the session is destroyed both client-side AND server-side


Token 
- Stateless
- Generally meant Json Web Tokens (JWT)
- Server does NOT keep a record of which users are logged in or which JWTs have been issued. Instead, every request to the server is accompanied by a token which the server uses to verify the authenticity of the request
1. Users enters their login credentials
2. Server verifies the credentials are correct and returns a signed token
3. This token is stored client side, most commonly in local storage but can be stored in session storage or a cookie as well
4. Subsequent requests to the server include this token as an additional Authorization header or through one of the other methods mentioned above
5. The server decodes the Json Web Token and if the token is valid processes the request
6. Once a user logs out, the token is destoryed client-side

## What is XSS? Types?

Cross Site Scripting attacks are a type of injection in which malicious scripts are injected into a web browser on a web application

Stored - Injected script is stored on the target server in a database, message form, comment field, etc...
Reflected - Injected script is reflected off the web server such as in an error message, search result, etc..
DOM - Injected payload modifies the DOM in the victims browser used by the original client side script so that the client code run in an unexpected manner

## What are the common defenses against XSS?

Input validation and Output Sanitization