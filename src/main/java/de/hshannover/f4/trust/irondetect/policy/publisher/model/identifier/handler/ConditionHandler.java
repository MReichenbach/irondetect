package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Condition;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class ConditionHandler extends ExtendetIdentifierHandler<Condition> {

	@Override
	public Element toExtendetElement(Identifier i, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(i, this);

		Condition condition = (Condition) i;

		String id = condition.getID();
		List<String> expressions = condition.getExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Condition with null expressions not allowed");
		}

		Element conditionElement = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,
				PolicyStrings.CONDITION_EL_NAME);
		Element idElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);

		List<Element> expressionElements = super.buildExpressionElements(expressions, doc);

		idElement.setTextContent(id);

		conditionElement.appendChild(idElement);
		super.appendListAsChild(conditionElement, expressionElements);

		Helpers.addAdministrativeDomain(conditionElement, condition);

		return conditionElement;
	}

	@Override
	public Class<Condition> handles() {
		return Condition.class;
	}

}
