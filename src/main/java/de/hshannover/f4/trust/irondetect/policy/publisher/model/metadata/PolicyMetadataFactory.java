package de.hshannover.f4.trust.irondetect.policy.publisher.model.metadata;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.ifmapj.log.IfmapJLog;
import de.hshannover.f4.trust.ifmapj.metadata.Cardinality;
import de.hshannover.f4.trust.ifmapj.metadata.StandardIfmapMetadataFactory;
import de.hshannover.f4.trust.irondetect.gui.ResultObject;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class PolicyMetadataFactory {

	private StandardIfmapMetadataFactory mMetadataFactory;

	private DocumentBuilder mDocumentBuilder;

	public PolicyMetadataFactory(){
		mMetadataFactory = IfmapJ.createStandardMetadataFactory();

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

	public Document createHasPolicy() {
		Document doc = mMetadataFactory.create("has-policy", "policy", PolicyStrings.POLICY_METADATA_NS_URI, Cardinality.multiValue);

		return doc;
	}

	public Document createHasElement() {
		Document doc = mMetadataFactory.create("has-element", "policy", PolicyStrings.POLICY_METADATA_NS_URI, Cardinality.multiValue);

		return doc;
	}

	public Document createRevMetadata(String elementName, String type, Document revMetadata, Identifier firstIdentifier)
			throws DOMException, MarshalException {
		return createRevMetadata(elementName, type, revMetadata, firstIdentifier, null, Collections.EMPTY_MAP);
	}

	public Document createRevMetadata(String elementName, String type, Document revMetadata,
			Identifier firstIdentifier, Identifier secondIdentifier, Map<String, String> attributes)
			throws DOMException, MarshalException {
		Document doc = mDocumentBuilder.newDocument();
		Element metadataElement = doc.createElementNS(PolicyStrings.REV_METADATA_NS_URI,
				PolicyStrings.REV_QUALIFIED_NAME + ":" + elementName);
		metadataElement.setAttributeNS(null, PolicyStrings.IFMAP_CARDINALITY, Cardinality.multiValue.toString());

		for (Map.Entry<String, String> attr : attributes.entrySet()) {
			metadataElement.setAttributeNS(null, attr.getKey(), attr.getValue());
		}

		Element revMetadataElement = doc.createElementNS(null, PolicyStrings.REV_METADATA);
		Element revFirstIdentifierElement = doc.createElementNS(null, PolicyStrings.REV_FIRST_IDENTIFIER);
		Element revSecondIdentifierElement = doc.createElementNS(null, PolicyStrings.REV_SECOND_IDENTIFIER);

		Element firstIdentifierElement = Identifiers.toElement(firstIdentifier, doc);
		
		revFirstIdentifierElement.appendChild(firstIdentifierElement);
		if (secondIdentifier != null) {
			revSecondIdentifierElement.appendChild(Identifiers.toElement(secondIdentifier, doc));
		}

		// Create a duplicate node and transfer ownership of the new node into the destination document
		Node revMetadataRootElementClone = revMetadata.getDocumentElement().cloneNode(true);
		doc.adoptNode(revMetadataRootElementClone);
		// Place the node in the new document
		revMetadataElement.appendChild(revMetadataRootElementClone);
		// addStandardMetadataAttributes(revMetadataElement, revMetadata); // unnötig
		revMetadataElement.appendChild(revFirstIdentifierElement);
		if (secondIdentifier != null) {
			revMetadataElement.appendChild(revSecondIdentifierElement);
		}

		metadataElement.appendChild(revMetadataElement);

		doc.appendChild(metadataElement);
		doc.createAttributeNS(PolicyStrings.REV_METADATA_NS_URI, PolicyStrings.REV_QUALIFIED_NAME);

		return doc;
	}

	public Document createPolicyActionMetadata(String elementName, ResultObject ruleResult,
			Map<ResultObject, List<String>> signatureFeatureMap,
			Map<ResultObject, Map<ResultObject, List<String>>> anomalyMap, Map<Document, Identity> featureDocuments)
			throws DOMException, MarshalException {

		Document doc = mDocumentBuilder.newDocument();
		Element metadataElement = doc.createElementNS(PolicyStrings.REV_METADATA_NS_URI,
				PolicyStrings.REV_QUALIFIED_NAME + ":" + elementName);
		metadataElement.setAttributeNS(null, PolicyStrings.IFMAP_CARDINALITY, Cardinality.multiValue.toString());

		addRuleResults(metadataElement, ruleResult, doc);
		addSignatureResults(metadataElement, signatureFeatureMap, doc);
		addAnomalyResults(metadataElement, anomalyMap, doc);

		for (Entry<Document, Identity> entry : featureDocuments.entrySet()) {
			Document mapDocument = entry.getKey();
			Identity mapIdentity = entry.getValue();

			Element revMetadataElement = doc.createElementNS(null, PolicyStrings.FEATURE_EL_NAME);

			// # build new metadata element
			// Create a duplicate node and transfer ownership of the new node into the destination document
			Node revMetadataRootElementClone = mapDocument.getDocumentElement().cloneNode(true);
			doc.adoptNode(revMetadataRootElementClone);
			// Place the node in the new document
			revMetadataElement.appendChild(revMetadataRootElementClone);

			// # build new Identity element
			Element identifierElement = Identifiers.toElement(mapIdentity, doc);
			revMetadataElement.appendChild(identifierElement);

			metadataElement.appendChild(revMetadataElement);
		}

		doc.appendChild(metadataElement);
		doc.createAttributeNS(PolicyStrings.REV_METADATA_NS_URI, PolicyStrings.REV_QUALIFIED_NAME);

		return doc;
	}

	private void addRuleResults(Element metadataElement, ResultObject ruleResultObject, Document doc) {
		String ruleDevice = ruleResultObject.getDevice();
		String ruleId = ruleResultObject.getId();
		String ruleResult = String.valueOf(ruleResultObject.getValue());

		Element deviceElement = doc.createElementNS(null, PolicyStrings.DEVICE_EL_NAME);
		Element ruleElement = doc.createElementNS(null, PolicyStrings.RULE_RESULT_EL_NAME);
		Element ruleIdElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);
		Element ruleResultElement = doc.createElementNS(null, PolicyStrings.RESULT_EL_NAME);

		deviceElement.setTextContent(ruleDevice);
		ruleIdElement.setTextContent(ruleId);
		ruleResultElement.setTextContent(ruleResult);

		ruleElement.appendChild(ruleIdElement);
		ruleElement.appendChild(ruleResultElement);

		metadataElement.appendChild(deviceElement);
		metadataElement.appendChild(ruleElement);
	}

	private void addAnomalyResults(Element metadataElement, Map<ResultObject, Map<ResultObject,
			List<String>>> anomalyMap, Document doc) {

		for (Entry<ResultObject, Map<ResultObject, List<String>>> anomaly : anomalyMap.entrySet()) {
			ResultObject anomalyResultObject = anomaly.getKey();
			String anomalyId = anomalyResultObject.getId();
			String anomalyResult = String.valueOf(anomalyResultObject.getValue());

			Element anomalyElement = doc.createElementNS(null, PolicyStrings.ANOMALY_RESULT_EL_NAME);
			Element anomalyIdElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);
			Element anomalyResultElement = doc.createElementNS(null, PolicyStrings.RESULT_EL_NAME);

			anomalyIdElement.setTextContent(anomalyId);
			anomalyResultElement.setTextContent(anomalyResult);

			anomalyElement.appendChild(anomalyIdElement);
			anomalyElement.appendChild(anomalyResultElement);

			for (Entry<ResultObject, List<String>> hint : anomaly.getValue().entrySet()) {
				ResultObject hintResultObject = hint.getKey();
				String hintId = hintResultObject.getId();
				String hintResult = String.valueOf(hintResultObject.getValue());

				Element hintElement = doc.createElementNS(null, PolicyStrings.HINT_RESULT_EL_NAME);
				Element hintIdElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);
				Element hintResultElement = doc.createElementNS(null, PolicyStrings.RESULT_EL_NAME);

				hintIdElement.setTextContent(hintId);
				hintResultElement.setTextContent(hintResult);

				hintElement.appendChild(hintIdElement);
				hintElement.appendChild(hintResultElement);

				anomalyElement.appendChild(hintElement);
			}
			metadataElement.appendChild(anomalyElement);
		}

	}

	private void addSignatureResults(Element metadataElement, Map<ResultObject, List<String>> signatureFeatureMap,
			Document doc) {
		for (Entry<ResultObject, List<String>> signature : signatureFeatureMap.entrySet()) {
			ResultObject signatureResultObject = signature.getKey();
			String signatureId = signatureResultObject.getId();
			String signatureResult = String.valueOf(signatureResultObject.getValue());

			Element signatureElement = doc.createElementNS(null, PolicyStrings.SIGNATURE_RESULT_EL_NAME);
			Element signatureIdElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);
			Element signatureResultElement = doc.createElementNS(null, PolicyStrings.RESULT_EL_NAME);

			signatureIdElement.setTextContent(signatureId);
			signatureResultElement.setTextContent(signatureResult);

			signatureElement.appendChild(signatureIdElement);
			signatureElement.appendChild(signatureResultElement);

			metadataElement.appendChild(signatureElement);
		}
	}

	private void addStandardMetadataAttributes(Element metadataElement, Document metadataDocument) {
		String cardinality = getIfmapCardinality(metadataDocument);
		String publisherId = getIfmapPublisherId(metadataDocument);
		String timestamp = getIfmapTimestamp(metadataDocument);
		String timestampFraction = getIfmapTimestampFraction(metadataDocument);

		// TODO url xmlns fehlt noch
		metadataElement.setAttribute(PolicyStrings.IFMAP_CARDINALITY, cardinality);
		metadataElement.setAttribute(PolicyStrings.IFMAP_PUBLISHER_ID, publisherId);
		metadataElement.setAttribute(PolicyStrings.IFMAP_TIMESTAMP, timestamp);
		metadataElement.setAttribute(PolicyStrings.IFMAP_TIMESTAMP_FRACTION, timestampFraction);
	}

	private String getIfmapCardinality(Document document) {
		return getMetadataAttribute(PolicyStrings.IFMAP_CARDINALITY, document);
	}

	private String getIfmapPublisherId(Document document) {
		return getMetadataAttribute(PolicyStrings.IFMAP_PUBLISHER_ID, document);
	}

	private String getIfmapTimestamp(Document document) {
		return getMetadataAttribute(PolicyStrings.IFMAP_TIMESTAMP, document);
	}

	private String getIfmapTimestampFraction(Document document) {
		return getMetadataAttribute(PolicyStrings.IFMAP_TIMESTAMP_FRACTION, document);
	}

	private static String getMetadataAttribute(String name, Document document) {
		if (document.getFirstChild().getNodeType() == Node.ELEMENT_NODE) {
			Element firstElement = (Element) document.getFirstChild();
			return firstElement.getAttribute(name);
		}
		return null;
	}

}
