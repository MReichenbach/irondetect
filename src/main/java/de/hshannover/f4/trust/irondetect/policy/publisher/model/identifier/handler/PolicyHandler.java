package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Policy;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class PolicyHandler extends ExtendetIdentifierHandler<Policy> {

	@Override
	public Element toExtendetElement(Identifier i, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(i, this);

		Policy policy = (Policy) i;

		String id = policy.getID();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		Element policyElement = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,
				PolicyStrings.POLICY_EL_NAME);
		Element idElement = doc.createElementNS(null, PolicyStrings.ID_EL_NAME);
		idElement.setTextContent(id);

		policyElement.appendChild(idElement);

		Helpers.addAdministrativeDomain(policyElement, policy);

		return policyElement;
	}

	@Override
	public Class<Policy> handles() {
		return Policy.class;
	}

}
