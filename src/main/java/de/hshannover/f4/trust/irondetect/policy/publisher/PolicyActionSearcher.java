package de.hshannover.f4.trust.irondetect.policy.publisher;

import static de.hshannover.f4.trust.irondetect.gui.ResultObjectType.POLICY;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.ifmapj.identifier.IdentityType;
import de.hshannover.f4.trust.ifmapj.log.IfmapJLog;
import de.hshannover.f4.trust.ifmapj.messages.PollResult;
import de.hshannover.f4.trust.ifmapj.messages.ResultItem;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult;
import de.hshannover.f4.trust.irondetect.gui.ResultObject;
import de.hshannover.f4.trust.irondetect.gui.ResultObjectType;
import de.hshannover.f4.trust.irondetect.model.Policy;
import de.hshannover.f4.trust.irondetect.model.Rule;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;
import de.hshannover.f4.trust.irondetect.util.Constants;
import de.hshannover.f4.trust.irondetect.util.Pair;
import de.hshannover.f4.trust.irondetect.util.PollResultReceiver;
import de.hshannover.f4.trust.irondetect.util.event.ResultUpdateEvent;

public class PolicyActionSearcher implements Runnable, PollResultReceiver {

	private static final Logger LOGGER = Logger.getLogger(PolicyActionSearcher.class);

	private static final String ESUKOM_CATEGORY_IDENTIFIER = "32939:category";

	private static final String FEATURE_TYPE_NAME = "feature";

	private static final String XMLNS_FEATURE_URL_PREFIX = "xmlns:esukom";

	private static final String ESUKOM_URL = "http://www.esukom.de/2012/ifmap-metadata/1";

	private LinkedBlockingQueue<PollResult> mNewPollResults = new LinkedBlockingQueue<PollResult>();

	private LinkedBlockingQueue<Pair<ResultObject, Document>> mNewPolicyAction = new LinkedBlockingQueue<Pair<ResultObject, Document>>();

	private PolicyActionUpdater mPolicyActionUpdater;

	private Policy mPolicy;

	private Map<String, Integer> mAlertInstanceNumber;

	private Map<Identity, List<Document>> mAlertResults;

	private DocumentBuilder mDocumentBuilder;

	private Thread mPolicyActionSearcherThread;

	public PolicyActionSearcher(PolicyActionUpdater policyActionUpdater, Policy policy) throws IfmapErrorResult,
			IfmapException {
		mPolicyActionUpdater = policyActionUpdater;
		mPolicy = policy;
		mAlertInstanceNumber = new HashMap<String, Integer>();
		mAlertResults = new HashMap<Identity, List<Document>>();

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			mDocumentBuilder = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			// TODO eigenen log
			IfmapJLog.error("Could not get DocumentBuilder instance [" + e.getMessage() + "]");
			throw new RuntimeException(e);
		}
	}
	
	private String findFeatureIdElement(Element root) {
		NodeList childs = root.getChildNodes();

		Node idNode = childs.item(0);
		if (idNode != null && "id".equals(idNode.getLocalName())) {
			Node idValueNode = idNode.getFirstChild();
			if (idValueNode != null && idValueNode.getNodeType() == Node.TEXT_NODE) {
				return idValueNode.getTextContent();
			} else {
				LOGGER.debug("First element of 'id' Node, is no TEXT_NODE");
				return null; // TODO EXCEPTION
			}

		} else {
			LOGGER.debug("First element child item 0, is no 'id' Node");
			return null; // TODO EXCEPTION
		}

	}

	/**
	 * Submit a new {@link PollResult} to this {@link PolicyActionSearcher}.
	 *
	 * @param pollResult A new {@link PollResult} to submit
	 */
	@Override
	public void submitNewPollResult(PollResult pollResult) {
		LOGGER.info("new Poll-Result...");
		if (checkPollResultHasEsukomAlertFeatures(pollResult)) {
			Map<Identity, List<Document>> alertResults = preparePollResult(pollResult);
			synchronized (mAlertResults) {
				mAlertResults.putAll(alertResults);
			}
			if (mPolicyActionSearcherThread != null) {
				synchronized (mPolicyActionSearcherThread) {
					LOGGER.debug("notify() ... new PollResult");
					mPolicyActionSearcherThread.notify();
				}
			}
		} else {
			LOGGER.info("poll-result has no EsukomFeatures");
		}
		LOGGER.info("... new Poll-Result submitted");
	}

	private Map<Identity, List<Document>> preparePollResult(PollResult pollResult) {
		Map<Identity, List<Document>> alertResults = new HashMap<Identity, List<Document>>();
		
		for (SearchResult searchResult : pollResult.getResults()) {
			for (ResultItem resultItem : searchResult.getResultItems()) {
				Identifier identifier1 = resultItem.getIdentifier1();
				Identifier identifier2 = resultItem.getIdentifier2();
				Identifier identifier;

				// A feature can not stand between two identifier. One of them must be null.
				if (!(identifier1 != null && identifier2 == null)) {
					if (!(identifier1 == null && identifier2 != null)) {
						LOGGER.debug("A feature can not stand between two identifier. One of them must be null. Next result item ...");
						continue;
					} else {
						identifier = resultItem.getIdentifier2();
						LOGGER.debug("One of the two identifiers is null(Identifier1), greate");
					}
				} else {
					identifier = resultItem.getIdentifier1();
					LOGGER.debug("One of the two identifiers is null(Identifier2), greate");
				}

				if (checkOfEsukomAlertIdentity(identifier)) {
					Identity identity = (Identity) identifier;
					if (!alertResults.containsKey(identity)) {
						alertResults.put(identity, new ArrayList<Document>());
					}
					for (Document metadata : resultItem.getMetadata()) {
						if (checkOfEsukomFeatureMetadata(metadata)) {
							alertResults.get(identity).add(metadata);
						}
					}
				}
			}
		}

		return alertResults;
	}

	private boolean checkPollResultHasEsukomAlertFeatures(PollResult pollResult) {
		for (SearchResult searchResult : pollResult.getResults()) {
			for (ResultItem resultItem : searchResult.getResultItems()) {
				Identifier identifier1 = resultItem.getIdentifier1();
				Identifier identifier2 = resultItem.getIdentifier2();
				Identifier identifier;

				// A feature can not stand between two identifier. One of them must be null.
				if (!(identifier1 != null && identifier2 == null)) {
					if (!(identifier1 == null && identifier2 != null)) {
						LOGGER.debug("A feature can not stand between two identifier. One of them must be null. Next result item ...");
						continue;
					} else {
						identifier = resultItem.getIdentifier2();
						LOGGER.debug("One of the two identifiers is null(Identifier1), greate");
					}
				} else {
					identifier = resultItem.getIdentifier1();
					LOGGER.debug("One of the two identifiers is null(Identifier2), greate");
				}

				if (checkOfEsukomAlertIdentity(identifier)) {
					for (Document metadata : resultItem.getMetadata()) {
						if (checkOfEsukomFeatureMetadata(metadata)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	private boolean checkIdentityIdentifier(Identifier identifier){
		if (identifier instanceof Identity) {
			return true;
		} else {
			return false;
		}
	}

	private boolean checkIdentityType(Identity identity) {
		if (identity.getType() == IdentityType.other) {
			return true;
		} else {
			return false;
		}
	}

	private boolean checkIdentityOtherTypeDefinition(Identity identity) {
		if (identity.getOtherTypeDefinition().equals(ESUKOM_CATEGORY_IDENTIFIER)) {
			return true;
		} else {
			return false;
		}
	}

	private boolean checkOfEsukomCategoryIdentity(Identifier identifier) {
		// TODO von debug auf trace ändern wenn fertig
		LOGGER.debug("check of esukom category identity");

		if (!checkIdentityIdentifier(identifier)) {
			LOGGER.debug("identifier is not a identity");
			return false;
		}

		Identity identity = (Identity) identifier;

		if (!checkIdentityType(identity)) {
			LOGGER.debug("identity type is no " + IdentityType.other);
			return false;
		}

		if (!checkIdentityOtherTypeDefinition(identity)) {
			LOGGER.debug("identity have a wrong esukom category");
			return false;
		}

		return true;
	}

	private boolean checkOfEsukomAlertIdentity(Identifier identifier) {

		if (!checkOfEsukomCategoryIdentity(identifier)) {
			return false;
		}

		Identity identity = (Identity) identifier;

		if (!checkIdentityName(identity)) {
			return false;
		}
		return true;
	}

	private boolean checkOfEsukomAlertIdentity(Identifier identifier, int alertInstanceNumber) {

		if (!checkOfEsukomAlertIdentity(identifier)) {
			return false;
		}

		Identity identity = (Identity) identifier;

		if (!checkIdentityName(identity, alertInstanceNumber)) {
			return false;
		}
		return true;
	}

	private boolean checkIdentityName(Identity identity) {
		if (!identity.getName().toLowerCase().startsWith((Constants.ALERT_IDENTIFIER_NAME))) {
			return false;
		}
		return true;
	}

	private boolean checkIdentityName(Identity identity, int alertInstanceNumber) {
		if (!identity.getName().toLowerCase().startsWith((Constants.ALERT_IDENTIFIER_NAME + ":" + alertInstanceNumber))) {
			return false;
		}
		return true;
	}

	private boolean checkOfEsukomFeatureMetadata(Document document) {
		// TODO von debug auf trace ändern wenn fertig
		LOGGER.debug("check of esukom feature metadata");
		String typename = document.getDocumentElement().getLocalName();
		String url = document.getDocumentElement().getAttribute(XMLNS_FEATURE_URL_PREFIX);

		if (!FEATURE_TYPE_NAME.equals(typename)) {
			LOGGER.debug("is not a feature metadata");
			return false;
		}

		if (!ESUKOM_URL.equals(url)) {
			LOGGER.debug("wrong esukom feature metadata url");
			return false;
		}

		return true;
	}

	private Document clone(Document document) {
		Document documentClone = mDocumentBuilder.newDocument();

		Node rootNodeClone = document.getDocumentElement().cloneNode(true);
		documentClone.adoptNode(rootNodeClone);
		documentClone.appendChild(rootNodeClone);

		return documentClone;
	}

	@Override
	public void run() {
		LOGGER.info("run() ...");
		mPolicyActionSearcherThread = Thread.currentThread();
		while (!Thread.currentThread().isInterrupted()) {
			try {

				LOGGER.info("warte auf neues policyActionMetadata ...");
				Pair<ResultObject, Document> policyAction = mNewPolicyAction.take();
				LOGGER.info("... take() policyActionMetadata");

				ResultObject ruleResult = policyAction.getFirstElement();
				Document policyActionMetadata = policyAction.getSecondElement();
				String device = ruleResult.getDevice();

				int actionCount = getActionCount(ruleResult.getId());
				
				for (int i = 0; i < actionCount; i++) {
					Document policyActionMetadataCopy = clone(policyActionMetadata);
					int alertInstanceNumber = 0;
					if (mAlertInstanceNumber.containsKey(device)) {
						alertInstanceNumber = mAlertInstanceNumber.get(device);
					}

					Identity identity = Identifiers.createIdentity(IdentityType.other, Constants.ALERT_IDENTIFIER_NAME
							+ ":" + alertInstanceNumber, device, Constants.OTHER_TYPE_DEFINITION);

					List<Document> alertFeatures = mAlertResults.get(identity);

					if (alertFeatures == null) {
						do {
							synchronized (Thread.currentThread()) {
								LOGGER.debug("wait() for new PollResult...");
								Thread.currentThread().wait();
								LOGGER.debug("... new PollResult");
							}
							alertFeatures = mAlertResults.get(identity);
						} while (alertFeatures == null);
					}

					addActionFeatures(policyActionMetadataCopy, alertFeatures, identity);

					mPolicyActionUpdater.sendPolicyAction(policyActionMetadataCopy, ruleResult.getId());

					alertInstanceNumber++;
					mAlertInstanceNumber.put(device, alertInstanceNumber);

					synchronized (mAlertResults) {
						mAlertResults.remove(identity);
					}

				}
			} catch (InterruptedException | ClassNotFoundException | InstantiationException | IllegalAccessException
					| IfmapErrorResult | IfmapException e) {
				LOGGER.error(e.getClass().getSimpleName() + " when take a new Poll-Result");
				break;
			}
		}
            
        LOGGER.info("... run()");
	}
	
	private void addActionFeatures(Document policyActionMetadata, List<Document> alertFeatures, Identity identity)
			throws MarshalException {
		Element rootElement = policyActionMetadata.getDocumentElement();

		for (Document feature : alertFeatures) {
			Element revMetadataElement = policyActionMetadata.createElementNS(null, PolicyStrings.ACTION_EL_NAME);

			// # build new metadata element
			// Create a duplicate node and transfer ownership of the new node into the destination document
			Node revMetadataRootElementClone = feature.getDocumentElement().cloneNode(true);
			policyActionMetadata.adoptNode(revMetadataRootElementClone);
			// Place the node in the new document
			revMetadataElement.appendChild(revMetadataRootElementClone);

			// # build new Identity element
			Element identifierElement = Identifiers.toElement(identity, policyActionMetadata);
			revMetadataElement.appendChild(identifierElement);

			rootElement.appendChild(revMetadataElement);
		}
	}

	private Map<Document, Identity> getFeatureMetadata(PollResult pollResult, String device, int alertInstanceNumber) {
		// TODO ist noch nicht device save
		Map<Document, Identity> featureDocuments = new HashMap<Document, Identity>();

		for (SearchResult searchResult : pollResult.getResults()) {
			for (ResultItem resultItem : searchResult.getResultItems()) {
				Identifier identifier1 = resultItem.getIdentifier1();
				Identifier identifier2 = resultItem.getIdentifier2();
				Identifier identifier;

				// A feature can not stand between two identifier. One of them must be null.
				if (!(identifier1 != null && identifier2 == null)) {
					if (!(identifier1 == null && identifier2 != null)) {
						LOGGER.debug("A feature can not stand between two identifier. One of them must be null. Next result item ...");
						continue;
					} else {
						identifier = resultItem.getIdentifier2();
						LOGGER.debug("One of the two identifiers is null(Identifier1), greate");
					}
				} else {
					identifier = resultItem.getIdentifier1();
					LOGGER.debug("One of the two identifiers is null(Identifier2), greate");
				}

				if (checkOfEsukomAlertIdentity(identifier, alertInstanceNumber)) {
					Identity identity = (Identity) identifier;
					if (device.equals(identity.getAdministrativeDomain())) {
						for (Document metadata : resultItem.getMetadata()) {
							if (checkOfEsukomFeatureMetadata(metadata)) {
								featureDocuments.put(metadata, identity);
							}
						}
					}
				}
			}
		}

		return featureDocuments;
	}

	private boolean checkPollResultIsFinished(ResultUpdateEvent updateEvent){
		ResultObject result = updateEvent.getPayload();
		if (!checkResultType(result, POLICY)) {
			return false;
		}
		return result.getValue();
	}

	private int getActionCount(String policyRuleId) {
		for (Rule r : mPolicy.getRuleSet()) {
			if (r.getId().equalsIgnoreCase(policyRuleId)) {
				return r.getActions().size();
			}
		}
		return -1;
	}

	private boolean checkResultType(ResultObject result, ResultObjectType... type) {
		if (Arrays.asList(type).contains(result.getType())) {
				return true;
		}
		return false;
	}

	public void submitNewPolicyAction(Pair<ResultObject, Document> policyAction) {
		LOGGER.info("new NewPolicyAction...");
		try {
			mNewPolicyAction.put(policyAction);
		} catch (InterruptedException e) {
			LOGGER.error("InterruptedException when submit new result-update: " + e.getMessage());
		}
	}

}
