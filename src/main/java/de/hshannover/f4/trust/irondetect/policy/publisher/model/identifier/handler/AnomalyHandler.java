package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler;

import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Anomaly;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class AnomalyHandler extends ExtendetIdentifierHandler<Anomaly> {

	@Override
	public Element toExtendetElement(Identifier i, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(i, this);

		Anomaly anomaly = (Anomaly) i;

		String id = anomaly.getID();
		List<String> expressions = anomaly.getExpressions();
		Map<String, List<String>> context = anomaly.getContext();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Anomaly with null expressions not allowed");
		}

		if (context == null) {
			throw new MarshalException("Anomaly with null context not allowed");
		}

		Element anomalyElement = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,
				PolicyStrings.ANOMALY_EL_NAME);
		Element idElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);

		List<Element> expressionElements = super.buildExpressionElements(expressions, doc);
		List<Element> contextElements = super.buildContextElements(context, doc);

		idElement.setTextContent(id);

		anomalyElement.appendChild(idElement);
		super.appendListAsChild(anomalyElement, expressionElements);
		super.appendListAsChild(anomalyElement, contextElements);

		Helpers.addAdministrativeDomain(anomalyElement, anomaly);

		return anomalyElement;
	}

	@Override
	public Class<Anomaly> handles() {
		return Anomaly.class;
	}

}
