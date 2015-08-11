package de.hshannover.f4.trust.irondetect.policy.publisher.test;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler.ExtendetIdentifierHandler;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class Signature5Handler extends ExtendetIdentifierHandler<Signature5> {

	@Override
	public Element toExtendetElement(Identifier identifier, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(identifier, this);

		Signature5 signature = (Signature5) identifier;
		String id = signature.getID();
		String expressions = signature.getFeatureExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Identity with null featureExpressions not allowed");
		}

		Element signature5Element = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,PolicyStrings.SIGNATURE_EL_NAME+5);
		Element idElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);
		Element featureExpressionElement1 = buildFeatureExpressionElement(null, "&quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.RECEIVE_BOOT_COMPLETED&quot;",doc);
		Element featureExpressionElement2 = buildFeatureExpressionElement("and", "&quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.CAMERA&quot;",doc);
		Element featureExpressionElement3 = buildFeatureExpressionElement("and", "&quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.INTERNET&quot;",doc);
		Element parameterExpressionElement1 = buildparameterExpression(null, "&quot;DATETIME&quot; &gt; &quot;06:00&quot;", doc);
		Element parameterExpressionElement2 = buildparameterExpression("and", "&quot;DATETIME&quot; &lt; &quot;22:00&quot;", doc);
		Element contextElement = buildContextElement("ctxWorkingHours", doc, parameterExpressionElement1, parameterExpressionElement2);

		Text signatureTxtId = doc.createTextNode(id);

		idElement.appendChild(signatureTxtId);

		signature5Element.appendChild(idElement);
		signature5Element.appendChild(featureExpressionElement1);
		signature5Element.appendChild(featureExpressionElement2);
		signature5Element.appendChild(featureExpressionElement3);
		signature5Element.appendChild(contextElement);

		Helpers.addAdministrativeDomain(signature5Element, signature);

		return signature5Element;
	}

	private Element buildFeatureExpressionElement(String booleanOperator, String expression, Document doc){
		Element featureExpressionElement = doc.createElementNS(null,PolicyStrings.FEATURE_EXPRESSION_EL_NAME);

		Element expressionElement = doc.createElement(PolicyStrings.EXPRESSION_EL_NAME);
		expressionElement.setTextContent(expression);

		if(booleanOperator != null){
			featureExpressionElement.setAttribute(PolicyStrings.BOOLEAN_OPERATOR_EL_NAME, booleanOperator);
		}
		featureExpressionElement.appendChild(expressionElement);

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

	private Element buildparameterExpression(String booleanOperator, String expression, Document doc){
		Element parameterExpressionElement = doc.createElement(PolicyStrings.PARAMETER_EXPRESSION_EL_NAME);

		Element expressionElement = doc.createElementNS(null,PolicyStrings.EXPRESSION_EL_NAME);
		expressionElement.setTextContent(expression);

		if(booleanOperator != null){
			parameterExpressionElement.setAttribute(PolicyStrings.BOOLEAN_OPERATOR_EL_NAME, booleanOperator);
		}
		parameterExpressionElement.appendChild(expressionElement);

		return parameterExpressionElement;
	}

	@Override
	public Class<Signature5> handles() {
		return Signature5.class;
	}

}
