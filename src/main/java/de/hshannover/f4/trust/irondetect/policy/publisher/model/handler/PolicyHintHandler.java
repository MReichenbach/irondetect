package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import static de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings.DEFAULT_ADMINISTRATIVE_DOMAIN;

import java.util.ArrayList;
import java.util.List;

import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Hint;

public class PolicyHintHandler implements PolicyHandler<de.hshannover.f4.trust.irondetect.model.Hint> {

	@Override
	public Hint toIdentifier(de.hshannover.f4.trust.irondetect.model.Hint data) {
		List<String> expressions = new ArrayList<String>();

		String hintId = data.getId();
		String procedure = data.getProcedure().getId();
		String value = data.getProcedure().getConfig();

		for (String featureId : data.getFeatureIds()) {
			StringBuilder sb = new StringBuilder();
			sb.append(featureId);
			sb.append(' ');
			sb.append(procedure);
			sb.append(' ');
			sb.append(value);
			expressions.add(sb.toString());
		}

		Hint identifier = new Hint(hintId, expressions, DEFAULT_ADMINISTRATIVE_DOMAIN);

		return identifier;
	}

	@Override
	public Class<de.hshannover.f4.trust.irondetect.model.Hint> handle() {
		return de.hshannover.f4.trust.irondetect.model.Hint.class;
	}

}
