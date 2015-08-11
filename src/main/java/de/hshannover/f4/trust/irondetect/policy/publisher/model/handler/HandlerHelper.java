package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.hshannover.f4.trust.irondetect.model.ConditionElement;
import de.hshannover.f4.trust.irondetect.model.Context;
import de.hshannover.f4.trust.irondetect.model.ContextParameterPol;
import de.hshannover.f4.trust.irondetect.model.FeatureExpression;
import de.hshannover.f4.trust.irondetect.model.HintExpression;
import de.hshannover.f4.trust.irondetect.util.BooleanOperator;
import de.hshannover.f4.trust.irondetect.util.Pair;

public class HandlerHelper {

	static Map<String, List<String>> transformContext(List<Context> contextSet) {
		Map<String, List<String>> context = new HashMap<String, List<String>>();

		for (Context c : contextSet) {
			for (Pair<ContextParameterPol, BooleanOperator> contexPair : c.getCtxParamSet()) {
				StringBuilder sb = new StringBuilder();

				String contextId = c.getId();
				String parameterType = contexPair.getFirstElement().getType().getName();
				String comparisonOperator = contexPair.getFirstElement().getComparisonOperator().valueOf();
				String parameterValue = contexPair.getFirstElement().getValue();

				if (contexPair.getSecondElement() != null) {
					String booleanOperator = contexPair.getSecondElement().toString();
					sb.append(booleanOperator);
					sb.append(' ');
				}

				sb.append(parameterType);
				sb.append(' ');
				sb.append(comparisonOperator);
				sb.append(' ');
				sb.append(parameterValue);

				if (!context.containsKey(contextId)) {
					context.put(contextId, new ArrayList<String>());
				}

				context.get(contextId).add(sb.toString());
			}
		}

		return context;
	}

	static List<String> transformFeatureExpression(List<Pair<FeatureExpression, BooleanOperator>> expressions) {
		List<String> stringExpressions = new ArrayList<String>();

		for (Pair<FeatureExpression, BooleanOperator> p : expressions) {
			StringBuilder sb = new StringBuilder();

			if (p.getSecondElement() != null) {
				String booleanOperator = p.getSecondElement().toString();
				sb.append(booleanOperator);
				sb.append(' ');
			}
			String feature = p.getFirstElement().getFeatureValuePair().getFirstElement();
			String comparisonOperator = p.getFirstElement().getFeatureValuePair().getSecondElement().getFirstElement()
					.valueOf();
			String featureValue = p.getFirstElement().getFeatureValuePair().getSecondElement().getSecondElement();

			sb.append(feature);
			sb.append(' ');
			sb.append(comparisonOperator);
			sb.append(' ');
			sb.append(featureValue);

			stringExpressions.add(sb.toString());
		}

		return stringExpressions;
	}

	static List<String> transformHintExpression(List<Pair<HintExpression, BooleanOperator>> expressions) {
		List<String> stringExpressions = new ArrayList<String>();

		for (Pair<HintExpression, BooleanOperator> p : expressions) {
			StringBuilder sb = new StringBuilder();

			if (p.getSecondElement() != null) {
				String booleanOperator = p.getSecondElement().toString();
				sb.append(booleanOperator);
				sb.append(' ');
			}

			String hintId = p.getFirstElement().getHintValuePair().getFirstElement().getId();
			String comparisonOperator = p.getFirstElement().getHintValuePair().getSecondElement().getFirstElement()
					.valueOf();
			String hintValue = p.getFirstElement().getHintValuePair().getSecondElement().getSecondElement();

			sb.append(hintId);
			sb.append(' ');
			sb.append(comparisonOperator);
			sb.append(' ');
			sb.append(hintValue);

			stringExpressions.add(sb.toString());
		}

		return stringExpressions;
	}

	public static List<String> transformConditionExpression(List<Pair<ConditionElement, BooleanOperator>> conditionSet) {
		List<String> stringExpressions = new ArrayList<String>();

		for (Pair<ConditionElement, BooleanOperator> p : conditionSet) {
			StringBuilder sb = new StringBuilder();

			if (p.getSecondElement() != null) {
				String booleanOperator = p.getSecondElement().toString();
				sb.append(booleanOperator);
				sb.append(' ');
			}

			String conditionElementId = p.getFirstElement().getId();

			sb.append(conditionElementId);

			stringExpressions.add(sb.toString());
		}

		return stringExpressions;
	}

}
