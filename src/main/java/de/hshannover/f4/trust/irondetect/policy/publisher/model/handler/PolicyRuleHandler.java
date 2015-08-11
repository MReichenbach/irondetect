package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import static de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings.DEFAULT_ADMINISTRATIVE_DOMAIN;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Rule;

public class PolicyRuleHandler implements PolicyHandler<de.hshannover.f4.trust.irondetect.model.Rule> {

	@Override
	public Rule toIdentifier(de.hshannover.f4.trust.irondetect.model.Rule data) {
		String ruleId = data.getId();

		Rule identifier = new Rule(ruleId, DEFAULT_ADMINISTRATIVE_DOMAIN);

		return identifier;
	}

	@Override
	public Class<de.hshannover.f4.trust.irondetect.model.Rule> handle() {
		return de.hshannover.f4.trust.irondetect.model.Rule.class;
	}

}
