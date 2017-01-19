<?php
namespace Sblmasta;

use Duo\Web;

/**
 * @author sblmasta@gmail.com
 *
 * Class AuthManager
 * @package DuoSecurity
 */
class AuthManager
{
    /**
     * @var string
     */
    private $akey;

    /**
     * @var string
     */
    private $ikey;

    /**
     * @var string
     */
    private $skey;

    /**
     * @var string
     */
    private $api_host;

    /**
     * @var string
     */
    private $user;

    /**
     * @var string
     * After authenticated action
     * In this route action you have to logg in your user for the application
     * If empty iframe will redirect to the current page
     */
    private $post_action = '';

    /**
     * AuthManager constructor.
     * @param mixed $akey DUO Application key is unique. You have to generate it in application side, 40 characters string.
     * @param mixed $ikey DUO ikey, You have to get it from DUO Security service
     * @param mixed $skey DUO skey is important secret string to API calls
     * @param mixed $apiHost Unique API url generated in application service
     */
    public function __construct($akey, $ikey, $skey, $apiHost)
    {
        $this->akey = $akey;
        $this->ikey = $ikey;
        $this->skey = $skey;
        $this->api_host = $apiHost;
    }

    /**
     * @param string $username Username like a string name or email
     * @return $this
     */
    public function setUserName($username)
    {
        $this->user = $username;

        return $this;
    }

    /**
     * @return string
     */
    public function getUserName()
    {
        return $this->user;
    }

    /**
     * @param string $action Type a action to send sig_response after authenticate
     * @return $this
     */
    public function setPostAction($action)
    {
        $this->post_action = $action;

        return $this;
    }

    /**
     * @return string
     */
    public function getPostAction()
    {
        return $this->post_action;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function generateSignRequest()
    {
        if (!$this->user) {
            throw new \Exception('Username can\'t be empty!');
        }

        $signRequest = Web::signRequest($this->ikey, $this->skey, $this->akey, $this->user);

        return $signRequest;
    }

    /**
     * @param string $signResponse This is response call from DUO mechanism, received as sig_response in $_POST
     * @return bool|null
     */
    public function verifySignRequest($signResponse)
    {
        $authenticated = Web::verifyResponse($this->ikey, $this->skey, $this->akey, $signResponse);

        if ($authenticated) {
            return $authenticated;
        }

        return false;
    }

    /**
     * @param mixed $id Type html ID tag for other actions like CSS or JS <iframe id="foobar"
     * @return string
     */
    public function generateIframeHtml($id = null)
    {
        $config = [
            'id' => ($id ? $id : 'duo_iframe'),
            'data-host' => $this->api_host,
            'data-sig-request' => $this->generateSignRequest(),
            'data-post-action' => $this->getPostAction(),
            'frameborder' => 0,
        ];
        $html = '<iframe';

        foreach ($config as $index => $value) {
            $html = $html . ' ' . $index . '="' . $value . '"';
        }

        $html = $html . '></iframe>';

        return $html;
    }
}
