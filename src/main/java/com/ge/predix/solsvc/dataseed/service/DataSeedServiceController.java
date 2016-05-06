package com.ge.predix.solsvc.dataseed.service;


import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.Header;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.multipart.MultipartFile;

import com.ge.predix.solsvc.bootstrap.ams.common.AssetRestConfig;
import com.ge.predix.solsvc.dataseed.asset.AssetDataInitialization;
import com.ge.predix.solsvc.dataseed.asset.ClassificationDataInitialization;
import com.ge.predix.solsvc.dataseed.asset.GroupDataInitialization;
import com.ge.predix.solsvc.dataseed.asset.MeterDataInitialization;
import com.ge.predix.solsvc.dataseed.util.SpreadSheetParser;
import com.ge.predix.solsvc.restclient.config.IOauthRestConfig;
import com.ge.predix.solsvc.restclient.impl.RestClient;

//import com.ge.predix.solsvc.dataseed.asset.AssetDataInitialization;

/**
 * 
 * @author predix -
 */
@RestController
public class DataSeedServiceController
{
    private static final Logger              log = LoggerFactory.getLogger(DataSeedServiceController.class);

    @Autowired
    private AssetDataInitialization          assetDataInit;

    @Autowired
    private MeterDataInitialization          meterDataInit;

    @Autowired
    private GroupDataInitialization          groupDataInit;

    @Autowired
    private ClassificationDataInitialization classDataInit;

    @Autowired
    private IOauthRestConfig                 restConfig;

    @Autowired
    private HttpServletRequest               context;

    @Autowired
    private RestClient                       restClient;

    @Autowired
    private AssetRestConfig                  assetRestConfig;

    @Value("${acsSubZone:#{null}}")
    private String                           acsSubZone;
    

    /**
     * @param file
     *            -
     * @param authorization
     *            -
     * @param appId
     *            -
     * @return -
     */

    @SuppressWarnings("nls")
    private String uploadAssetData(MultipartFile file, String authorization, String appId)
    {
        String name = file.getName();
        List<String> workSheets = new ArrayList<String>();
        workSheets.add("Asset");
        workSheets.add("Fields");
        workSheets.add("Meter");
        workSheets.add("Classification");
        workSheets.add("Group");

        if ( !file.isEmpty() )
        {
            try
            {
                SpreadSheetParser parser = new SpreadSheetParser();
                Map<String, String[][]> content = parser.parseInputFile(file.getInputStream(), workSheets);

                List<Header> headers = new ArrayList<Header>();
                log.debug("zoneId=" + this.assetRestConfig.getZoneId());
                headers = this.restClient.getSecureTokenForClientId();
                this.restClient.addZoneToHeaders(headers, this.assetRestConfig.getZoneId());

                this.classDataInit.seedData(content, headers);
                this.groupDataInit.seedData(content, headers);
                this.meterDataInit.seedData(content, headers);
                this.assetDataInit.seedData(content, headers);
                return "You successfully uploaded " + name + "!";
            }
            catch (Exception e)
            {
                log.error("", e);
                return "You failed to upload " + name + " => " + e.getMessage();
            }
        }
        return "You failed to upload " + name + " because the file was empty.";
    }

    /**
     * The method is called from the index.html to upload the Asset.xls spreadsheet to import data into Asset . 
     * This api redirects to validateUser endpoint with username and password. This validateUser endpoint is protected by ACS using acs-security-extension using spring security.
     * The configuration for the acs-security-extension using spring-security is located in the src/main/resources/META-INF/spring/dataseed-service-acs-context.xml . 
     * The spring security extension , based on the username , password and setting on the VCAPS or application.properties , calls the OAuth provider to get the token and check on the
     * ACS to evaluate the policy.Once the policy is evaluated to PERMIT , then the call is pass forward to the get the token based on client credentials and call asset endpoints.
     * Spring Security acs-extension  if the policy evaluated is condition is resolved to  DENY , this then raises an OAuth2AccessDeniedException and the same exception is reported . 
     * @param username - 
     * @param password -
     * @param file -
     * @param appId -=
     * @return -
     */
    @SuppressWarnings("nls")
    @RequestMapping(value = "/uploadAssetData", method = RequestMethod.POST)
    public @ResponseBody String uploadAssetData(@RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "password", required = true) String password,
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "appId", defaultValue = "rmdapp") String appId)
    {
    	// 1. Create a OAuthRestTemplate to call the validateUser endpoint.
        OAuth2RestTemplate restTemplate = getRestTemplate(username, password);
        MultiValueMap<String, Object> map = new LinkedMultiValueMap<String, Object>();
        String dataseedUrl = this.context.getRequestURL().toString().replace("/uploadAssetData", "/validateuser");
        dataseedUrl = dataseedUrl.replaceAll("http","https"); // this is requires since all traffice will be https

        log.info("XXXCalling dataseed URL " + dataseedUrl);
        
        // 2 . ValidateUser endpoint is protected by ACS using acs-security-extension using spring security.
        //The configuration for the acs-security-extension using spring-security is located in the src/main/resources/META-INF/spring/dataseed-service-acs-context.xml . 
        //The spring security extension , based on the username , password and setting on the VCAPS or application.properties , calls the OAuth provider to get the token and check on the
       // ACS to evaluate the policy.Once the policy is evaluated to PERMIT , then the call is pass forward to the get the token based on client credentials and call asset endpoints.
        try
        {
         	String token = null;
        	//3. Once the policy is evaluated to PERMIT , then the call is pass forward to the get the token based on client credentials and call asset endpoints.
            token = restTemplate.postForObject(new URI(dataseedUrl), new HttpEntity<MultiValueMap<String, Object>>(map),
                    String.class);
           
            String response = uploadAssetData(file, token, appId);
            return response;
        }
        //4 .If the policy evaluated is condition is resolved to  DENY , this then raises an OAuth2AccessDeniedException and the same exception is returned back as response.
       catch (OAuth2AccessDeniedException e)
       {
    	   log.error("Error validating user "+username+" with following error " +e.getCause() +e.getMessage() + e);
            throw new RuntimeException(e);
         
       }
       catch( Exception e)
        {
     	   log.error("Error uplaoding Asset for user "+username+" with following error " + e.getCause() + e.getMessage() + e);
           throw new RuntimeException(e);
          
        }

    }

    /**
     * Returns a OAuth2RestTemplate based on the username password
     * @param username
     * @param password
     * @return
     */
    @SuppressWarnings("nls")
    private OAuth2RestTemplate getRestTemplate(String username, String password)
    {
        // get token here based on username password;
        ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
        resourceDetails.setUsername(username);
        resourceDetails.setPassword(password);
        String url = this.restConfig.getOauthResourceProtocol() + "://" + this.restConfig.getOauthRestHost()
                + this.restConfig.getOauthResource();
        resourceDetails.setAccessTokenUri(url);
        String[] clientids = this.restConfig.getOauthClientId().split(":");
        resourceDetails.setClientId(clientids[0]);
        resourceDetails.setClientSecret(clientids[1]);
        
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails);
      
        return restTemplate;
    }

    /**
     * Endpoint is gated with ACS and validates the policy for condition by spring security Interceptors and filters. 
     * The configuration for the acs-security-extension using spring-security is located in the src/main/resources/META-INF/spring/dataseed-service-acs-context.xml.
     * If the policy is evaluated to success , the call proceeds to generate token based on client_credentials and returns this token back to the caller .
     * @param username -
     * @param password -
     * @return -
     * @throws Exception -
     */
    @SuppressWarnings("nls")
    @RequestMapping(value = "/validateuser", method = RequestMethod.POST)
    public String validateUser() throws Exception
    {
    	
    	//Get token based on the client_credentials to access Asset and timeseries
    	 log.info("getting token based on the client_credentials");
    	String authorization = null;
    	try {
    		ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
    	    String url = this.restConfig.getOauthResourceProtocol() + "://" + this.restConfig.getOauthRestHost()
    	                + this.restConfig.getOauthResource();
    	    resourceDetails.setAccessTokenUri(url);
    	    String[] clientids = this.restConfig.getOauthClientId().split(":");
    	    resourceDetails.setClientId(clientids[0]);
    	    resourceDetails.setClientSecret(clientids[1]);
    	    
    	    OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails);
    	    OAuth2AccessToken token = restTemplate.getAccessToken();
     
	        authorization = token.getTokenType() + " " + token.getValue();
    	}   catch (HttpClientErrorException hce) {
        	throw new Exception(hce);
        }
        return authorization;

    }

}
