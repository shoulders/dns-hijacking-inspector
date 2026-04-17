<?php
/*
 * @package   QWcrm
 * @author    Jon Brown https://quantumwarp.com/
 * @copyright Copyright (C) 2026 Jon Brown, All rights reserved.
 * @license   GNU/GPLv3 or later; https://www.gnu.org/licenses/gpl.html
 */

class Inspector {

    // Settings
    private $useForm                    = true;
    private $testDomain                 = 'madeup123abc.com';
    private $nameserverInternalStandard = '10.0.0.1';
    private $nameserverInternalDot      = '10.0.0.1';
    private $nameserverInternalDoh      = 'https://10.0.0.1/dns-query';
    private $nameserverExternalStandard = '9.9.9.9';
    private $nameserverExternalDot      = '9.9.9.9';
    private $nameserverExternalDoh      = 'https://dns.quad9.net/dns-query';

    // Prerequsites
    private $minimumPhpVersion = '8.1';
    private $requiredPhpExtensions = ['openssl','curl', 'hash', 'intl'];

    // Holding Variables
    private $results = array();
    private $nonPresentExtensions = array();
    private $output = '';
    private $testDomainIps = array();
    private $testDomainIpsDisplayString = '';
    private $dnsHijackingStatus = true;
    public static $curlVERIFYPEER = false;  // Temporary Workaround - DoH Peer Verification
    public static $curlVERIFYHOST = false;  // Temporary Workaround - DoH Peer Verification

    /**
     * set everything up and run
     */
    public function __construct()
    {
        $this->checkPrerequisites();
        $this->buildTopBlock();
        if($this->useForm){
            $this->buildForm();
        }
        if(!$this->useForm || ($this->useForm && isset($_POST['submit']))){
            $this->processData();
            $this->buildResults();
        }
        $this->buildBottomBlock();
        echo($this->output);
    }

    /**
     * Check Prerequisites are met
     *
     * @return void
     */
    private function checkPrerequisites(){

        $message = '';

        // Check minimum PHP version is met
        if (version_compare(PHP_VERSION, $this->minimumPhpVersion , '<')) {
            $message .= ('<p>This script requires PHP'.$this->minimumPhpVersion .' '.'or later to run. Your current version is '.PHP_VERSION.'</p>');
        }

        // Check required extensions are loaded and if not, flag them
        foreach ($this->requiredPhpExtensions as $extension){
            if (!extension_loaded($extension)) {
                $this->nonPresentExtensions[] = $extension;
            }
        }

        // If extensions are flagged missing, stop and echo message to screen
        if(!empty($this->nonPresentExtensions)) {
            $message .= '<ul>';
            foreach ($this->nonPresentExtensions as $extension){
                $message .= '<li>'.$extension.'</li>';
            }
            $message .= '</ul>';
        }

        // If there are missing prerequsites then stop with error message
        if($message){die($message);}

        // Autoload dependencies
        require __DIR__ . '/vendor/autoload.php';

    }

    /**
     * Process the data supplied
     *
     * @return void
     */
    private function processData(){

        // Build results matrix
        $this->results['internalStandard']        = $this->dnsRequest('internal', 'standard',   $this->nameserverInternalStandard,  $this->testDomain);
        $this->results['internalDot']             = $this->dnsRequest('internal', 'dot',        $this->nameserverInternalDot,       $this->testDomain);
        $this->results['internalDotUnverified']   = $this->dnsRequest('internal', 'dot',        $this->nameserverInternalDot,       $this->testDomain, false);
        $this->results['internalDoh']             = $this->dnsRequest('internal', 'doh',        $this->nameserverInternalDoh,       $this->testDomain);
        $this->results['internalDohUnverified']   = $this->dnsRequest('internal', 'doh',        $this->nameserverInternalDoh,       $this->testDomain, false);
        $this->results['externalStandard']        = $this->dnsRequest('external', 'standard',   $this->nameserverExternalStandard,  $this->testDomain);
        $this->results['externalDot']             = $this->dnsRequest('external', 'dot',        $this->nameserverExternalDot,       $this->testDomain);
        $this->results['externalDotUnverified']   = $this->dnsRequest('external', 'dot',        $this->nameserverExternalDot,       $this->testDomain, false);
        $this->results['externalDoh']             = $this->dnsRequest('external', 'doh',        $this->nameserverExternalDoh,       $this->testDomain);
        $this->results['externalDohUnverified']   = $this->dnsRequest('external', 'doh',        $this->nameserverExternalDoh,       $this->testDomain, false);

        // Calculate if DNS Hijacking was successful
        foreach($this->results as $key => $value){

            // Skip testing internal requests
            if($value['targetNetwork'] === 'internal'){continue;}

            // Test Blocking rules - I need to test for NXDOMAIN - This shows a DNS request escaped to an external DNS server
            if($value['NXDOMAIN']){$this->dnsHijackingStatus = false;}

            // Test Redirect Rules - If any external responses, have any IPs (successful response), and the Test Domain's IP is not there, then hijacking has failed
            if(!empty($value['addresses']) && !array_intersect($this->testDomainIps, $value['addresses'])){$this->dnsHijackingStatus = false;}
        }

        // Make the `dnsHijackingStatus` printable
        $this->dnsHijackingStatus = $this->dnsHijackingStatus ? '<span style="color: green;">Successful</span>' : '<span style="color: red;">Failed</span>';
    }

    /**
     * This function performs the DNS lookup
     *
     * @param [type] $targetNetwork
     * @param [type] $requestType
     * @param [type] $nameserver
     * @param [type] $targetDomain
     * @param boolean $verifyPeer
     * @return void
     */
    private function dnsRequest($targetNetwork, $requestType, $nameserver, $targetDomain, $verifyPeer = true){

        self::$curlVERIFYPEER = false;  // Temporary Workaround - DoH Peer Verification
        self::$curlVERIFYHOST = false;  // Temporary Workaround - DoH Peer Verification

        // Build the result array
        $result = array('targetNetwork' => $targetNetwork, 'displayMsg' => null, 'addresses' => array(), 'NXDOMAIN' => null, 'status' => null);

        try
        {
            // Create new resolver object, passing in an array of (Nameservers | DoH servers) to use for lookups
            // If domains are passed rather than IPs, DoH is used for the lookup.
            // Only https:// is supported for DoH
            $r = new \NetDNS2\Resolver(['nameservers' => [ $nameserver ]]);

            // Enable DoT / Upgrade standard cnnection to use TLS
            if ($requestType === 'dot'){$r->use_tls = true;}

            // Disable TLS Peer Verfication for DoT nameservers
            if(!$verifyPeer && ($requestType === 'dot')){
                $r->tls_context = [ 'verify_peer' => false, 'verify_peer_name' => false ];
            }

            // Disable TLS Peer Verfication for DoH nameservers
            if(!$verifyPeer && ($requestType === 'doh')){
                self::$curlVERIFYPEER = true;  // Temporary Workaround - DoH Peer Verification
                self::$curlVERIFYHOST = true;  // Temporary Workaround - DoH Peer Verification
            }

            // Execute the query request for the domain's A record
            $res = $r->query($targetDomain, 'A');

            // Get the response a string (Header, Question, Answer)
            //$stringVariable = (string) $res;

            // Loop through the returned addesses, build array and display string
            $addressesDisplayString = '';
            foreach($res->answer as $response){
                $result['addresses'][] = (string) $response->address;
                $addressesDisplayString .= $response->address.'<br>';
            }
            $addressesDisplayString = rtrim($addressesDisplayString, '<br>');

            // Get the the fake Domain's IPs from the first successful internal DNS request
            if($targetNetwork == 'internal' && empty($this->testDomainIps)){
                $this->testDomainIps = $result['addresses'];
                $this->testDomainIpsDisplayString = str_replace('<br>', ', ', $addressesDisplayString);
            }

            // Build Display Message based on if the Response from a redirected source
            // This test is a workaround test because I cannot get the Source IP from the DNS response packet
            // If I could read the Source IP then I might not need the non-existant domain congigured
            // If an external DNS request gets an IP for the non-existant domain, it must of been redirected to the internal router
            if($targetNetwork == 'external' && (in_array($this->testDomainIps, $result['addresses']))){
                $result['displayMsg'] = '<span style="color: orange;">'.$addressesDisplayString.'</span>';
                $result['status'] = 'redirected';
            } else {
                $result['displayMsg'] = '<span style="color: green;">'.$addressesDisplayString.'</span>';
                $result['status'] = 'success';
            }
        }

        catch(\NetDNS2\Exception $e)
        {
            // Workaround for GitHub #182 (DoH uses cURL so is not an issue)
            if($requestType === 'dot' && $verifyPeer && empty($e->getMessage())){
                $workaround = 'No Native error, most likely:<br><br>Error [tls]: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider. (os error -2146762487)';
            }

            // Set NXDOMAIN as needed (I do it this way because I do not know how to get test NXDOMAIN from the response)
            if($e->getMessage() == 'DNS request failed: The domain name referenced in the query does not exist.'){
                $result['NXDOMAIN'] = true;
            }

            // Set status and display message
            $result['displayMsg'] = '<span style="color: red;">'.($workaround ?? $e->getMessage()).'</span>';
            $result['status'] = 'failed';
        }

        return $result;

    }

    /**
     * Output common html to screen
     *
     * @return void
     */
    private function buildTopBlock(){

        $this->output .= <<<TOPBLOCK
            <style>
                table {border-collapse: collapse; /* Ensures borders don't double */}
                #userForm label{font-weight: bold;}
                #userForm input{width: 200px;}
                #results th, #results td{padding: 10px;}
                #results td.displayCell{width: 200px; border: 2px solid white; background-color: #e6e6e6;}
                .legendBlocks{display: inline-block; height:20px; width: 40px;}
                .legendBlocks.success{background-color: green;}
                .legendBlocks.redirected{background-color: orange;}
                .legendBlocks.failed{background-color: red;}
            </style>
            <div id="githubLink" style="float:right;">
            <a href="https://github.com/shoulders/dns-hijacking-inspector" target="_blank" rel="noopener">
            <img src="images/github-mark.png" alt="GitHub" style="width:50px;"><br>Instructions
            </a>
            </div>
        TOPBLOCK;
    }

    /**
     * Build form if requested
     *
     * @return void
     */
    private function buildForm(){

        // Use default values if none are submitted via $_POST
        $this->testDomain ?? $_POST['testDomain'] ?? $this->testDomain;
        $this->nameserverInternalStandard ?? $_POST['testDomain'] ?? $this->nameserverInternalStandard;
        $this->nameserverInternalDot ?? $_POST['testDomain'] ?? $this->nameserverInternalDot;
        $this->nameserverInternalDoh ?? $_POST['testDomain'] ?? $this->nameserverInternalDoh;
        $this->nameserverExternalStandard ?? $_POST['testDomain'] ?? $this->nameserverExternalStandard;
        $this->nameserverExternalDot ?? $_POST['testDomain'] ?? $this->nameserverExternalDot;
        $this->nameserverExternalDoh ?? $_POST['testDomain'] ?? $this->nameserverExternalDoh;

        $this->output .= <<<FORM
            <div id="userForm">
            <form action="inspector.php" method="post">
            <h1>Form</h1>
            <p>Enter the details as required and then run this from your local network.</p>
            <table>
            <tbody>
            <tr>
            <td><label for="testDomain">Test Domain:</label></td>
            <td><input type="text" name="testDomain" value="$this->testDomain" placeholder="madeup123abc.com" required></td>
            </tr>
            <tr>
            <td><label for="nameserverInternalStandard">Nameserver Internal Standard:</label></td>
            <td><input type="text" name="nameserverInternalStandard" value="$this->nameserverInternalStandard" placeholder="10.0.0.1" required></td>
            </tr>
            <tr>
            <td><label for="nameserverInternalDot">Nameserver Internal DoT:</label> </td>
            <td><input type="text" name="nameserverInternalDot" value="$this->nameserverInternalDot" placeholder="10.0.0.1" required></td>
            </tr>
            <tr>
            <td><label for="nameserverInternalDoh">Nameserver Internal DoH:</label></td>
            <td><input type="text" name="nameserverInternalDoh" value="$this->nameserverInternalDoh " placeholder="https://10.0.0.1/dns-query" required></td>
            </tr>
            <tr>
            <td><label for="nameserverExternalStandard">Nameserver External Standard:</label></td>
            <td><input type="text" name="nameserverExternalStandard" value="$this->nameserverExternalStandard" placeholder="9.9.9.9" required></td>
            </tr>
            <tr>
            <td><label for="nameserverExternalDot">Nameserver External DoT:</label></td>
            <td><input type="text" name="nameserverExternalDot" value="$this->nameserverExternalDot" placeholder="9.9.9.9" required></td>
            </tr>
            <tr>
            <td><label for="nameserverExternalDoh">Nameserver External DoH:</label></td>
            <td><input type="text" name="nameserverExternalDoh" value="$this->nameserverExternalDoh" placeholder="https://dns.quad9.net/dns-query" required></td>
            </tr>
            </tbody>
            </table>
            <input type="submit" name="submit" value="Submit">
            </form>

        FORM;
    }

    /**
     * Build the results
     *
     * @return void
     */
    private function buildResults(){

    $this->output .= <<<RESULTS
        <div id="results">
        <h1>Results</h1>
        <p><strong>Test Domain: </strong>$this->testDomain<br /><strong>Test Domain IP(s): </strong>$this->testDomainIpsDisplayString</p>
        <table>
        <thead>
        <tr>
        <td> </td>
        <td><strong>Standard (53)</strong></td>
        <td><strong>DoT (853)</strong></td>
        <td><strong>DoH (80)</strong></td>
        <td> </td>
        </tr>
        </thead>
        <tbody>
        <tr>
        <td rowspan="2"><strong>Internal</strong></td>
        <td class="displayCell" rowspan="2">{$this->results['internalStandard']['displayMsg']}</td>
        <td class="displayCell">{$this->results['internalDot']['displayMsg']}</td>
        <td class="displayCell">{$this->results['internalDoh']['displayMsg']}</td>
        <td><strong>Verified</strong></td>
        </tr>
        <tr>
        <td class="displayCell">{$this->results['internalDotUnverified']['displayMsg']}</td>
        <td class="displayCell">{$this->results['internalDohUnverified']['displayMsg']}</td>
        <td><strong>Unverified</strong></td>
        </tr>
        <tr>
        <td rowspan="2"><strong>External</strong></td>
        <td class="displayCell" rowspan="2">{$this->results['externalStandard']['displayMsg']}</td>
        <td class="displayCell">{$this->results['externalDot']['displayMsg']}</td>
        <td class="displayCell">{$this->results['externalDoh']['displayMsg']}</td>
        <td><strong>Verified</strong></td>
        </tr>
        <tr>
        <td class="displayCell">{$this->results['externalDotUnverified']['displayMsg']}</td>
        <td class="displayCell">{$this->results['externalDohUnverified']['displayMsg']}</td>
        <td><strong>Unverified</strong></td>
        </tr>
        </tbody>
        </table>
        <div>
        <ul style="list-style-type: none;">
        <li><span class="legendBlocks success"></span> = Response received.</li>
        <li><span class="legendBlocks redirected"></span> = Response received, but the request was redirected.</li>
        <li><span class="legendBlocks failed"></span> = Request was Blocked or Failed.</li>
        </ul>
        </div>
        <h2>DNS Hijacking Status = $this->dnsHijackingStatus</h2>
        </div>
    RESULTS;

    }
    /**
     * Output common html to screen
     *
     * @return void
     */
    private function buildBottomBlock(){

        $this->output .= <<<BOTTOMBLOCK

        <div>License = don't know yet</div>

        BOTTOMBLOCK;
    }
}

new Inspector;
