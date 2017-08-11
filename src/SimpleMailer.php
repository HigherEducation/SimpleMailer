<?php
/**
 * SimpleMailer - Wrapper for PHPMailer when emailing with Gmail over SMTP.
 * PHP Version 5
 * @package SimpleMailer
 * @link https://github.com/HigherEducation/SimpleMailer
 * @author Dave Robb <drobb@highereducation.com>
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 * @note This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

namespace HigherEducation\SimpleMailer;

class SimpleMailer
{
    /**
     * The SimpleMailer Version number.
     * @var string
     */
    public $Version = '0.1.0';

    /**
     * Is the email being sent as part of an AJAX request?
     * Determins whether to return a JSON response or throw a PHP exception on error
     * @var boolean
    */
    public $Ajax = false;

    /**
     * The receiving email address
     * Passed to and set by __construct() when a new SimpleMailer is instantiated
     * @var string
     * @access protected
     */
    protected $EmailTo;

    /**
     * Email address of the sender
     * Required. Must be set before calling send()
     * @var string
     */
    public $FromEmail;

    /**
     * Name of the sender
     * Required. Must be set before calling send()
     * @var string
     */
    public $FromName;

    /**
     * Gmail host address. Current value should work but can be overwritten if needed
     * @var string
     */
    public $GmailHost = 'smtp.gmail.com';

    /**
     * Password of the Gmail account the email should be sent through
     * Passed to and set by __construct() when a new SimpleMailer is instantiated
     * @var string
     * @access protected
     */
    protected $GmailPassword;

    /**
     * Gmail port. Current value should work but can be overwritten if needed
     * @var integer
     */
    public $GmailPort = 587;

    /**
     * Username of the Gmail account the email should be sent through
     * Passed to and set by __construct() when a new SimpleMailer is instantiated
     * @var string
     * @access protected
     */
    protected $GmailUsername;

    /**
     * SMTP secure protocol. TLS should work but can be changed to SSL if required
     * @var string
     */
    public $SMTPSecure = 'tls';

    /**
     * Email subject.  Can be set prior to calling send() or use default
     * @var string
     */
    public $Subject = 'New email from website';

    /**
     * Email content
     * Required. Must be set before calling send()
     * @var string
     */
    public $Message;

    /**
     * Email address to reply to
     * If not set before calling send() defaults to $FromEmail
     * @var string
     */
    public $ReplyTo;

    /**
     * CSRF token if desired (Recommended!)
     * Should be set by calling setToken($token) prior to calling send()
     * @var string
     */
    protected $Token;


    /**
     * Constructor.
     * $config['username'] Username for Gmail account email is to be sent through
     * $config['password'] Password for Gmail account email is to be sent through
     * $config['emailTo'] Email address email should be sent to
     * @param array $config Required configuration.
     * @return void on success or calls fail() on failure.
     */
    public function __construct(array $config)
    {
        if (empty($config['username'])) {
            $this->fail($message = 'Missing SMTP username', new \InvalidArgumentException($message));
        }
        $this->GmailUsername = $config['username'];

        if (empty($config['password'])) {
            $this->fail($message = 'Missing SMTP password', new \InvalidArgumentException($message));
        }
        $this->GmailPassword = $config['password'];

        if (empty($config['emailTo'])) {
            $this->fail($message = 'Missing receiving email address', new \InvalidArgumentException($message));
        }
        if (!filter_var($config['emailTo'], FILTER_VALIDATE_EMAIL)) {
            $this->fail($message = 'Invalid receiving email address', new \InvalidArgumentException($message));
        }
        $this->EmailTo = $config['emailTo'];
    }


    /**
     * Generate CSRF Token.
     * Strongly recommended this be used.  Stores token in user's session.
     * Returns same token as string to be used in form input
     * @return string
     * @link https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
     */
    public static function getToken()
    {
        if (empty($_SESSION['Token'])) {
            $_SESSION['Token'] = bin2hex(random_bytes(256));
        }
        return $_SESSION['Token'];
    }


    /**
     * Set $Token property.
     * @return void on success or calls fail() on failure.
     */
    public function setToken(string $token)
    {
        if (empty($token)) {
            $this->fail($message = 'SCRF token is empty', new \InvalidArgumentException($message));
        }
        $this->Token = $token;
    }


    /**
     * Check $Token property and value stored in session for a match.
     * If no match found, CSRF request assumed.
     * @return void on success or calls fail() on failure.
     * @access protected
     */
    protected function validateToken()
    {
        if (session_status() != PHP_SESSION_ACTIVE) {
            session_start();
        }

        if (!hash_equals($_SESSION['Token'], $this->Token)) {
            $this->fail($message = 'Invalid  token', new \Exception($message));
        }
    }


    /**
     * Validate minimum arguments required for sending an email.
     * Checks FromEmail, FromName and Message for presence.
     * Checks FromEmail against FILTER_VALIDATE_EMAIL.
     * @return void on success or calls fail() on failure.
     * @access protected
     */
    protected function validateArgs()
    {
        foreach (['FromEmail', 'FromName', 'Message'] as $required) {
            if (empty($this->$required)) {
                return $this->fail($message = 'Required property missing: ' . $required, new \Exception($message));
            }
        }

        if (!filter_var($this->FromEmail, FILTER_VALIDATE_EMAIL)) {
            return $this->fail($message = 'Sender email address is invalid', new \Exception($message));
        }

        if (empty($this->ReplyTo)) {
            $this->ReplyTo = $this->FromEmail;
        }
    }



    /**
     * Helper method to add some story to the email.
     * Add reference to website domain if available.
     * Add reference to URL of source form if available.
     * @param string unparsed message.
     * @return string parsed message
     */
    public function prepMessage($message)
    {
        $host     = !empty($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : false;
        $uri      = !empty($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : false;
        $parts[]  = sprintf('You have a new message from %s:', $host ? $host : 'your website');

        if (!empty($_SERVER['REQUEST_URI'])) {
            $parts[] = 'Submitted from URL: ' . ($host ? $host : '') . $_SERVER['REQUEST_URI'];
        }
        $parts[] = $message;
        return join("\n\n", $parts);
    }


    /**
     * Send email
     * @throws Exception
     * @return result of success() on success or fail() on failure.
     */
    public function send()
    {
        try {
            $this->validateArgs();

            if (!empty($this->Token)) {
                $this->validateToken();
            }

            $mail = new \PHPMailer(true);
            $mail->isSMTP();
            $mail->Host = $this->GmailHost;
            $mail->Port = $this->GmailPort;
            $mail->SMTPSecure = $this->SMTPSecure;
            $mail->SMTPAuth = true;
            $mail->Username = $this->GmailUsername;
            $mail->Password = $this->GmailPassword;
            $mail->setFrom($this->FromEmail, $this->FromName);
            $mail->addReplyTo($this->FromEmail);
            $mail->addAddress($this->EmailTo);
            $mail->Subject = $this->Subject;
            $mail->Body = $this->Message;
            return $mail->send() ? $this->success() : $this->fail($mail->ErrorInfo());
        } catch (\Exception $e) {
            $this->fail($e->getMessage(), new \Exception($e->getMessage()));
        }
    }


    /**
     * Handle successful email send
     * If $Ajax is set generate a header response code of 200
     * @return bool true
     */
    protected function success()
    {
        if ($this->Ajax) {
            http_response_code(200);
            exit;
        }
        return true;
    }


    /**
     * Handle failure somewhere along the pipeline
     * If $Ajax is set generate a header response code of 400.  Return JSON object with error
     * @throws Exception
     * @return void
     */
    protected function fail($message, $exception = false)
    {
        if ($this->Ajax) {
            http_response_code(400);
            echo json_encode([
              'status' => 400,
              'detail' => $message,
            ]);
            exit;
        }
        throw $exception;
    }
}
