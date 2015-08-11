package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import static de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings.DEFAULT_ADMINISTRATIVE_DOMAIN;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Policy;

public class PolicyPolicyHandler implements PolicyHandler<de.hshannover.f4.trust.irondetect.model.Policy> {

	@Override
	public Policy toIdentifier(de.hshannover.f4.trust.irondetect.model.Policy data) {
		String policyId = data.getId();

		Policy identifier = new Policy(policyId, DEFAULT_ADMINISTRATIVE_DOMAIN);

		return identifier;
	}

	@Override
	public Class<de.hshannover.f4.trust.irondetect.model.Policy> handle() {
		return de.hshannover.f4.trust.irondetect.model.Policy.class;
	}

}
