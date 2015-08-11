package de.hshannover.f4.trust.irondetect.policy.publisher.test;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler.ExtendetIdentifierHandler;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class Signature3Handler extends ExtendetIdentifierHandler<Signature3> {

	@Override
	public Element toExtendetElement(Identifier identifier, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(identifier, this);

		Signature3 signature = (Signature3) identifier;
		String id = signature.getID();
		String expressions = signature.getFeatureExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Identity with null featureExpressions not allowed");
		}

		Element signature3Element = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,PolicyStrings.SIGNATURE_EL_NAME+3);
		Element idElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);
		Element featureExpressionElement1 = buildFeatureExpressionElement(null, "&quot;smartphone.android.app.permission.granted&quot;", "=", "&quot;android.permission.RECEIVE_BOOT_COMPLETED&quot;",doc);
		Element featureExpressionElement2 = buildFeatureExpressionElement("and", "&quot;smartphone.android.app.permission.granted&quot;", "=", "&quot;android.permission.CAMERA&quot;",doc);
		Element featureExpressionElement3 = buildFeatureExpressionElement("and", "&quot;smartphone.android.app.permission.granted&quot;", "=", "&quot;android.permission.INTERNET&quot;",doc);
		Element parameterExpressionElement1 = buildparameterExpression(null, "&quot;DATETIME&quot;", "GT", "&quot;06:00&quot;", doc);
		Element parameterExpressionElement2 = buildparameterExpression("and", "&quot;DATETIME&quot;", "ST", "&quot;22:00&quot;", doc);
		Element contextElement = buildContextElement("ctxWorkingHours", doc, parameterExpressionElement1, parameterExpressionElement2);

		Text signatureTxtId = doc.createTextNode(id);

		idElement.appendChild(signatureTxtId);

		signature3Element.appendChild(idElement);
		signature3Element.appendChild(featureExpressionElement1);
		signature3Element.appendChild(featureExpressionElement2);
		signature3Element.appendChild(featureExpressionElement3);
		signature3Element.appendChild(contextElement);

		Helpers.addAdministrativeDomain(signature3Element, signature);

		return signature3Element;
	}

	private Element buildFeatureExpressionElement(String booleanOperator, String feature, String comparisonOperator, String value, Document doc){
		Element featureExpressionElement = doc.createElementNS(null,PolicyStrings.FEATURE_EXPRESSION_EL_NAME);

		Element featureElement = doc.createElementNS(null,PolicyStrings.FEATURE_EL_NAME);
		Element comparisonOperatorElement = doc.createElementNS(null,PolicyStrings.COMPARISON_OPERATOR_EL_NAME);
		Element valueElement = doc.createElementNS(null,PolicyStrings.VALUE_EL_NAME);

		Text featureTxt = doc.createTextNode(feature);
		Text comparisonOperatorTxt = doc.createTextNode(comparisonOperator);
		Text valueTxt = doc.createTextNode(value);

		featureElement.appendChild(featureTxt);
		comparisonOperatorElement.appendChild(comparisonOperatorTxt);
		valueElement.appendChild(valueTxt);

		if(booleanOperator != null){
			Element booleanOperatorElement = doc.createElementNS(null,PolicyStrings.BOOLEAN_OPERATOR_EL_NAME);
			Text booleanOperatorTxt = doc.createTextNode(booleanOperator);
			booleanOperatorElement.appendChild(booleanOperatorTxt);
			featureExpressionElement.appendChild(booleanOperatorElement);
		}
		featureExpressionElement.appendChild(featureElement);
		featureExpressionElement.appendChild(comparisonOperatorElement);
		featureExpressionElement.appendChild(valueElement);

		return featureExpressionElement;
	}

	private Element buildContextElement(String id, Document doc, Element... parameterExpressionElements){
		Element contextElement = doc.createElementNS(null,PolicyStrings.CONTEXT_EL_NAME);

		Element idElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);

		Text contextTxtId = doc.createTextNode(id);

		idElement.appendChild(contextTxtId);

		contextElement.appendChild(idElement);
		for(int i=0; i<parameterExpressionElements.length; i++){
			contextElement.appendChild(parameterExpressionElements[i]);
		}

		return contextElement;
	}

	private Element buildparameterExpression(String booleanOperator, String parameter, String comparisonOperator, String value, Document doc){
		Element parameterExpressionElement = doc.createElementNS(null,PolicyStrings.PARAMETER_EXPRESSION_EL_NAME);

		Element parameterElement = doc.createElementNS(null,PolicyStrings.PARAMETER_EL_NAME);
		Element comparisonOperatorElement = doc.createElementNS(null,PolicyStrings.COMPARISON_OPERATOR_EL_NAME);
		Element valueElement = doc.createElementNS(null,PolicyStrings.VALUE_EL_NAME);

		Text parameterTxt = doc.createTextNode(parameter);
		Text comparisonOperatorTxt = doc.createTextNode(comparisonOperator);
		Text valueTxt = doc.createTextNode(value);

		parameterElement.appendChild(parameterTxt);
		comparisonOperatorElement.appendChild(comparisonOperatorTxt);
		valueElement.appendChild(valueTxt);

		if(booleanOperator != null){
			Element booleanOperatorElement = doc.createElementNS(null,PolicyStrings.BOOLEAN_OPERATOR_EL_NAME);
			Text booleanOperatorTxt = doc.createTextNode(booleanOperator);
			booleanOperatorElement.appendChild(booleanOperatorTxt);
			parameterExpressionElement.appendChild(booleanOperatorElement);
		}
		parameterExpressionElement.appendChild(parameterElement);
		parameterExpressionElement.appendChild(comparisonOperatorElement);
		parameterExpressionElement.appendChild(valueElement);

		return parameterExpressionElement;
	}

	@Override
	public Class<Signature3> handles() {
		return Signature3.class;
	}

}
