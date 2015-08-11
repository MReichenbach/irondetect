/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de/
 * 
 * This file is part of irondetect, version 0.0.8,
 * implemented by the Trust@HsH research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2010 - 2015 Trust@HsH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
/**
 * 
 */
package de.hshannover.f4.trust.irondetect.ifmap;



import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.binding.IfmapStrings;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.config.BasicAuthConfig;
import de.hshannover.f4.trust.ifmapj.config.CertAuthConfig;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.InitializationException;
import de.hshannover.f4.trust.ifmapj.identifier.AccessRequest;
import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.IdentityType;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishElement;
import de.hshannover.f4.trust.ifmapj.messages.PublishNotify;
import de.hshannover.f4.trust.ifmapj.messages.PublishRequest;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.messages.ResultItem;
import de.hshannover.f4.trust.ifmapj.messages.SearchRequest;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult;
import de.hshannover.f4.trust.ifmapj.messages.SubscribeUpdate;
import de.hshannover.f4.trust.irondetect.util.Configuration;
import de.hshannover.f4.trust.irondetect.util.Constants;
import de.hshannover.f4.trust.irondetect.util.Triple;

/**
 * The {@link IfmapController} is responsible for fetching all changes related
 * to Feature or Category metadata from the MAPS. This is basically done by a
 * two-step approach:</br>
 * <ol>
 * <li>
 * For each PDP that is configured, a Subscription on the PDPs Device Identifier
 * is created (max-depth=2). This way, we are notified each time a new device is
 * authenticated by the PDP and we learn the Device Identifier of the new
 * endpoint.</li>
 * <li>
 * For each new endpoint, another Subscription is created to monitor the
 * Category and Feature metadata.</li>
 * </ol>
 * 
 * 
 * @author ibente
 * 
 */
public class IfmapController {

	private static final Logger logger = Logger
			.getLogger(IfmapController.class);

	/**
	 * The only SSRC
	 */
	private SSRC mSsrc;

	private String mPublisherId;

	private DocumentBuilder documentBuilder;

	private NewEventPoller mNewEventPoller;

	private NewDevicePoller mNewDevicePoller;

	private Map<String, Integer> mAlertInstanceNumber;
	
	/**
	 * @param ifmapToFeatureMapper
	 * 
	 */
	public IfmapController() {
		mAlertInstanceNumber = new HashMap<String, Integer>();

		try {
			initSsrc();
		} catch (FileNotFoundException e) {
			logger.error("Could not initialize truststore: " + e.getMessage());
			System.exit(Constants.RETURN_CODE_ERROR_TRUSTSTORE_LOADING_FAILED);
		} catch (InitializationException e) {
			logger.error("Could not initialize ifmapj: " + e.getMessage() + ", " + e.getCause());
			System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_INITIALIZATION_FAILED);
		}
		
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		try {
			this.documentBuilder = factory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			logger.error("Could not configure XML parser: " + e.getMessage() + ", " + e.getCause());
			System.exit(Constants.RETURN_CODE_ERROR_PARSER_CONFIGURATION_FAILED);
		}
		
		logger.info(IfmapController.class.getSimpleName() + " has started.");

		initSession();

		startWorker();
	}

	public void submitNewDevice(Device device) {
		try {
			this.mNewDevicePoller.put(device);
			logger.info("New device was submitted.");
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Load {@link TrustManager} instances and create {@link SSRC}.
	 * 
	 * @throws FileNotFoundException
	 * @throws InitializationException
	 */
	private void initSsrc() throws FileNotFoundException,
			InitializationException {
		String authMethod = Configuration.ifmapAuthMethod();
		
		String basicUrl = Configuration.ifmapUrlBasic();
		String certUrl = Configuration.ifmapUrlCert();
		String username = Configuration.irondetectDeviceSubscriberUser();
		String password = Configuration.irondetectDeviceSubscriberPassword();
		String trustStorePath = Configuration.keyStorePath();
		String trustStorePassword = Configuration.keyStorePassword();
		
		try {
			if (authMethod.equalsIgnoreCase("basic")) {
				logger.info("Creating SSRC using basic authentication to " + Configuration.ifmapUrlBasic());
				BasicAuthConfig basicConfig = new BasicAuthConfig(basicUrl, username, password, trustStorePath, trustStorePassword);
				this.mSsrc = IfmapJ.createSsrc(basicConfig);
			}
			else if (authMethod.equalsIgnoreCase("cert")) {
				logger.info("Creating SSRC using certificate-based authentication to " + Configuration.ifmapUrlCert());
				CertAuthConfig certConfig = new CertAuthConfig(certUrl, trustStorePath, trustStorePassword, trustStorePath, trustStorePassword);
				this.mSsrc= IfmapJ.createSsrc(certConfig);
			}
			else {
				throw new IllegalArgumentException("unknown authentication method '" + authMethod + "'");
			}
		} catch (InitializationException e) {
			logger.error("Could not initialize ifmapj: " + e.getMessage() + ", " + e.getCause());
			System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_INITIALIZATION_FAILED);
		}
	}

	private void initSession() {
		try {
			mSsrc.newSession(Configuration.ifmapMaxResultSize());
		} catch (IfmapErrorResult e) {
			logger.error("Got IfmapErrorResult: " + e.getMessage() + ", " + e.getCause());
		} catch (IfmapException e) {
			logger.error("Got IfmapException: " + e.getMessage() + ", " + e.getCause());
			System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_EXCEPTION);
		}
		
		logger.debug("Session initialized: Session ID: " + mSsrc.getSessionId()
				+ " - Publisher ID : " + mSsrc.getPublisherId() + " (with MAX_RESULT_SIZE = " + Configuration.ifmapMaxResultSize() + ")");
		mPublisherId = mSsrc.getPublisherId();
	}

	private void startWorker() {
		logger.debug("starting worker threads ...");

		DeviceSearcher searcher = new DeviceSearcher(this);
		Thread searcherThread = new Thread(searcher,
				DeviceSearcher.class.getSimpleName());
		searcherThread.start();

		EndpointPoller poller = EndpointPoller.getInstance();
		try {
			poller.setArc(mSsrc.getArc());
		} catch (InitializationException e) {
			logger.error("Could not initialize ifmapj: " + e.getMessage() + ", " + e.getCause());
			System.exit(Constants.RETURN_CODE_ERROR_IFMAPJ_INITIALIZATION_FAILED);
		}

		Thread pollerThread = new Thread(poller, EndpointPoller.class.getSimpleName());
		
		this.mNewEventPoller = new NewEventPoller(this);
		Thread eventPollerThread = new Thread(this.mNewEventPoller, NewEventPoller.class.getSimpleName());
		
		this.mNewDevicePoller = new NewDevicePoller(this);
		Thread devicePollerThread = new Thread(this.mNewDevicePoller, NewDevicePoller.class.getSimpleName());

		pollerThread.start();
		eventPollerThread.start();
		devicePollerThread.start();
	}

	/**
	 * @param device
	 * @throws IfmapErrorResult
	 * @throws IfmapException
	 */
	void subscribeForSmartphone(Device device) throws IfmapErrorResult,
			IfmapException {
		logger.debug("Subscribe for new smartphone device " + device + " ...");

		SubscribeUpdate subscribeUpdate = Requests.createSubscribeUpdate();

		try {
			subscribeUpdate.setName(createSHA1(device.getName()).substring(0,
                                device.getName().length() > 20 ? 19 : device.getName().length()-1));	// TODO FIXME hackhackhack
		} catch (NoSuchAlgorithmException e) {
			logger.error("SHA1ing failed.");
		}
		subscribeUpdate.setStartIdentifier(device);
		subscribeUpdate.setMaxDepth(10000); // FIXME maxDepth needed?
		subscribeUpdate.setMaxSize(Configuration.ifmapMaxResultSize());
		subscribeUpdate.setMatchLinksFilter(Constants.MATCH_LINKS_SMARTPHONE);

		subscribeUpdate.addNamespaceDeclaration("esukom", Constants.ESUKOM_NAMESPACE_URI);

		synchronized (mSsrc) {
			mSsrc.subscribe(Requests.createSubscribeReq(subscribeUpdate));
		}
		logger.debug("Subscription done!");
	}

	/**
	 * @param target
	 * @param event
	 */
	public void submitNewEvent(String device, List<Document> metadataList, boolean ifmapEvent) {
		try {
			this.mNewEventPoller.put(device, metadataList, ifmapEvent);
			logger.info("New Event was inserted.");
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @param event
	 */
	void publishEvent(Triple<String, List<Document>, Boolean> event) {
		logger.info("Trying to publish new action metadata");

		List<PublishElement> elements = new ArrayList<PublishElement>();
		
		String device = event.getFirstElement();
		List<Document> metadataList = event.getSecondElement();
		boolean ifmapEvent = event.getThirdElement();
		
		Identifier target = null;
		int tmpInstanceNumber = 0;
		
		if (mAlertInstanceNumber.containsKey(device)) {
			tmpInstanceNumber = mAlertInstanceNumber.get(device);
		}
		
		if (ifmapEvent) {
			target = searchAccessRequestDeviceIdentifier(device);
		} else {
			target = Identifiers.createIdentity(IdentityType.other,
					Constants.ALERT_IDENTIFIER_NAME + ":" + tmpInstanceNumber, device, Constants.OTHER_TYPE_DEFINITION);
			tmpInstanceNumber++;
			mAlertInstanceNumber.put(device, tmpInstanceNumber);
			
			logger.trace("Device name for new event: " + device);
			elements.add(createLinksForDevice(device, target));
		}
		
		if (Configuration.publishNotify()) {
			for (Document metadata : metadataList) {
				elements.add(Requests.createPublishNotify(target, metadata));
			}
		} else {
			for (Document metadata : metadataList) {
				elements.add(Requests.createPublishUpdate(target, metadata));
			}
		}

		if (elements.size() > 0) {
			PublishRequest request = Requests.createPublishReq(elements);

			try {
				synchronized (mSsrc) {
					mSsrc.publish(request);
				}
				logger.info("New action metadata was published.");
			} catch (IfmapErrorResult e) {
				logger.error("Got IfmapErrorResult: "+  e.getMessage() + ", " + e.getCause());
			} catch (IfmapException e) {
				logger.error("Got IfmapException: "+  e.getMessage() + ", " + e.getCause());
			}
		} else {
			logger.error("PublishElement was null.");
		}
	}

	/**
	 * @return
	 */
	public String getPublisherId() {
		return this.mPublisherId;
	}
	
	/**
	 * @param device
	 * @return
	 */
	private PublishElement createLinksForDevice(String device, Identifier alertFeature) {
		Document deviceCategory = this.documentBuilder.newDocument();
		Element e = deviceCategory.createElementNS(Constants.ESUKOM_NAMESPACE_URI, Constants.ESUKOM_NAMESPACE_PREFIX + ":" + "device-category");
		e.setAttributeNS(null, "ifmap-cardinality", "singleValue");
		
		deviceCategory.appendChild(e);
		
		logger.trace("Adding link to new alert-instance = " + mAlertInstanceNumber.get(device));
		
		if (Configuration.publishNotify()) {
			PublishNotify result = Requests.createPublishNotify();
			result.setIdentifier1(Identifiers.createDev(device));
			result.setIdentifier2(alertFeature);
			result.addMetadata(deviceCategory);
			return result;
		} else {
			PublishUpdate result = Requests.createPublishUpdate();
			result.setIdentifier1(Identifiers.createDev(device));
			result.setIdentifier2(alertFeature);
			result.addMetadata(deviceCategory);
			result.setLifeTime(MetadataLifetime.session);
			return result;
		}
	}
	
	/**
	 * @param device
	 * @return
	 */
	private Identifier searchAccessRequestDeviceIdentifier(String device) {
		Identifier startIdentifier = Identifiers.createDev(device);
		
		SearchRequest searchRequest = Requests.createSearchReq(Constants.MATCH_LINKS_ACCESS_REQUEST, 1, null, Configuration.ifmapMaxResultSize(), null, startIdentifier);
		searchRequest.addNamespaceDeclaration(IfmapStrings.BASE_PREFIX, IfmapStrings.BASE_NS_URI);
		searchRequest.addNamespaceDeclaration(IfmapStrings.STD_METADATA_PREFIX, IfmapStrings.STD_METADATA_NS_URI);
		try {
			SearchResult search;
			synchronized (mSsrc) {
				search = mSsrc.search(searchRequest);
			}
			List<ResultItem> resultItems = search.getResultItems();
			for (ResultItem resultItem : resultItems) {
				Identifier[] identifiers = resultItem.getIdentifier();
				for (int i = 0; i < identifiers.length; i++) {
					if (identifiers[i] instanceof AccessRequest) {
						return identifiers[i];
					}
				}
			}
		} catch (IfmapErrorResult e) {
			logger.error("Got IfmapErrorResult: "+  e.getMessage() + ", " + e.getCause());
		} catch (IfmapException e) {
			logger.error("Got IfmapExecption: "+  e.getMessage() + ", " + e.getCause());
		}
		
		return null;
	}
	
	/**
	 * From: http://www.sha1-online.com/sha1-java/
	 * 
	 * @param input
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String createSHA1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
         
        return sb.toString();
    }
}
