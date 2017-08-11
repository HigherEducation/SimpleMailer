# SimpleMailer
SimpleMailer is a wrapper for [PHPMailer](https://packagist.org/packages/phpmailer/phpmailer) when using Gmail over SMTP.  It's intended use is as a super-light replacement for WordPress plugins like GravityForms, if you don't need to store form data in the WordPress database or build forms using a GUI (ie, you provide the HTML form).  A simple use-case would be a basic contact form on your site where you want the data collected to be sent directly to an inbox.


### Object Instantiation
Each `SimpleMailer` object requires 3 values when instantiated:

 - `username`: Gmail username
 - `password`: Gmail password
 - `emailTo`: Email address the form should submit to

These should be passed to the class constructor as an associative array:

```php
$mailer = new SimpleMailer([
  "username" => "yourGmailUsername",
	"password" => "yourGmailPassword",
	"emailTo"  => "your@emailaddress.com"
]);
```

PSA: It's recommended that you read these values in from a file that lives outside your public web directory.

### Preparing to send an email from a submitted form
Before calling the `send()` method, there are 3 required object properties that must have values:

 - `$FromEmail`: sender's email address
 - `$FromName`: name of sender
 - `$Message`: email message

While it's assumed that you'll be asking your users for their name and email as part of the form data collection, you can populate these properties with any valid data you wish.  A simple example using the instantiated `$mailer` object from the previous stem (minus data validation) would be:

```php
$mailer->FromEmail = $_POST["email"];
$mailer->FromName = $_POST["name"];
$mailer->Message = $_POST["message"];
```

### Sending an Email
Once you have assigned values to the 3 required object properties you simply call the object `send()` method to send the email:

```php
$mailer->send();
```

### Message Formatting
You are in full control of the body of the message.  This means you can have forms with as many fields as you wish, as long as you build the message before assigning it to the `Message` property.

However to cover a broad use-case, SimpleMailer comes with a basic message formatter built in:

```php
$mailer->Message = $mailer->prepMessage($_POST["message"]);
```

This method will attempt to add the following boilerplate information to the start of your message:

```html
You have a new message from [yourdomain.com|your website]:

Submitted from URL: yourdomain.com/path/to/form/
```

### CSRF Protection
SimpleMailer comes with optional [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29) protection using a unique token generated for each user session.  Using the CSRF protection is a simple 2-step process.

First add a hidden field to your form and populate it with a token generated by the SimpleMailer class (you can name the field whatever you want):

```php
<input type="hidden" name="CSRFToken" value="<?php echo SimpleMailer::getToken(); ?>" />
```

Second, when the form is submitted assign the value of your hidden field containing the token to your object's `$Token` property:

```php
$mailer->Token = $_POST["CSRFToken"];
```

When you call the `send()` method on your object, this token will be validated against the token stored in the user's `$_SESSION`.  If they do not match CSRF is suspected and the method will return an error that you can catch.


### Choosing SimpleMailer Response Type
SimpleMailer offers 2 response types.  By default each point of failure in the class will throw an `Exception` that can be caught by your PHP:

```php
try {
  $mailer = new SimpleMailer([
    "username" => "yourGmailUsername",
    "password" => "yourGmailPassword"
  ]);
} catch (Exception $e) {
  echo "Something went wrong:" $e->getMessage();
  # Missing receiving email address
}
```

However it's a much nicer user experience to process a form with an AJAX request.  SimpleMailer can handle handle JSON error responses and send HTTP response codes that your script can action on by setting the `$Ajax` property:

```php
$mailer->Ajax = true;
```

Now SimpleMailer will handle the shutdown of your PHP script after sending the response headers and data back to the browser.

#### Example JSON error response:
```json
{
  "status": 400,
  "detail": "Required property missing: Message"
}
```


### AJAX Example
The following example assumes you're using JQuery and Composer to autoload classes.  If you're not autoloading (why?), you will need to include the class manually.

#### The Form

```php
<?php use HigherEducation\SimpleMailer\SimpleMailer; ?>

<form method="post" action="/contact/">
  <label>Full Name</label>
  <input type="text" name="name" />
  <label>Email</label>
  <input type="email" name="email" />
  <label>Comments/Questions</label>
  <textarea name="message"></textarea>
  <input type="hidden" name="token" value="<?php echo SimpleMailer::getToken(); ?>" />
  <button type="submit">Send</button>
</form>
```

#### The JS
```javascript
  $('form').submit(function(e) {
    e.preventDefault();
    var form = $(this);
    $.ajax({
      url: form.attr('action'),
      type: form.attr('method'),
      data: form.serialize(),
      success: function(data) {
        console.log("Success");
      },
      error: function(data) {
        console.log(data.responseText);
      }
    });
  });
```

#### Server Side Processing (contact.php)
```php
use HigherEducation\SimpleMailer\SimpleMailer;

if (empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
  http_response_code(403);
  exit;
}

$mailer = new SimpleMailer([
  "username" => "yourGmailUsername",
  "password" => "yourGmailPassword",
  "emailTo"  => "your@emailaddress.com"
]);

$mailer->Ajax       = true;
$mailer->FromEmail  = $_POST['email'];
$mailer->FromName   = $_POST['name'];
$mailer->Message    = $mailer->prepMessage($_POST['message']);
$mailer->setToken($_POST['token']);
$mailer->send();
```
