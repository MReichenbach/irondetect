package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Hint;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class HintHandler extends ExtendetIdentifierHandler<Hint> {

	@Override
	public Element toExtendetElement(Identifier i, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(i, this);

		Hint hint = (Hint) i;

		String id = hint.getID();
		List<String> expressions = hint.getExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Hint with null expressions not allowed");
		}

		Element hintElement = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,
				PolicyStrings.HINT_EL_NAME);
		Element idElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);

		List<Element> expressionElements = super.buildExpressionElements(expressions, doc);

		idElement.setTextContent(id);

		hintElement.appendChild(idElement);
		super.appendListAsChild(hintElement, expressionElements);

		Helpers.addAdministrativeDomain(hintElement, hint);

		return hintElement;
	}

	@Override
	public Class<Hint> handles() {
		return Hint.class;
	}

}
