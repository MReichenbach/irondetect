package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Action;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class ActionHandler extends ExtendetIdentifierHandler<Action> {

	@Override
	public Element toExtendetElement(Identifier i, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(i, this);

		Action action = (Action) i;

		String id = action.getID();
		List<String> expressions = action.getExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Action with null expressions not allowed");
		}

		Element actionElement = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,
				PolicyStrings.ACTION_EL_NAME);
		Element idElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);

		List<Element> expressionElements = super.buildExpressionElements(expressions, doc);

		idElement.setTextContent(id);

		actionElement.appendChild(idElement);
		super.appendListAsChild(actionElement, expressionElements);

		Helpers.addAdministrativeDomain(actionElement, action);

		return actionElement;
	}

	@Override
	public Class<Action> handles() {
		return Action.class;
	}

}
