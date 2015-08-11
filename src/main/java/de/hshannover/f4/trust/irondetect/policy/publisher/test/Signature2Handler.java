package de.hshannover.f4.trust.irondetect.policy.publisher.test;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.PolicyPublisherTest;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler.ExtendetIdentifierHandler;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class Signature2Handler extends ExtendetIdentifierHandler<Signature2> {

	@Override
	public Element toExtendetElement(Identifier identifier, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(identifier, this);

		Signature2 signature = (Signature2) identifier;
		String id = signature.getID();
		String expressions = signature.getFeatureExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Identity with null featureExpressions not allowed");
		}

		Element signature2Element = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,PolicyStrings.SIGNATURE_EL_NAME+2);
		Element test = doc.createElementNS(null, "TEST");
		Element idElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);
		Element featureExpressionsElement = doc.createElementNS(null,PolicyStrings.FEATURE_EXPRESSIONS_EL_NAME);

		Text signatureTxtId = doc.createTextNode(id);
		Text testTxt = doc.createTextNode("Testtesxt");
		Text signatureTxtExpressions = doc.createTextNode(expressions);

		idElement.appendChild(signatureTxtId);
		signature2Element.appendChild(idElement);

		featureExpressionsElement.appendChild(signatureTxtExpressions);

		signature2Element.appendChild(featureExpressionsElement);
		for(int i=0; i<2;i++){
			Element contextElement = doc.createElementNS(null,PolicyStrings.CONTEXT_EL_NAME);
			Element contextIdElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);
			Element parameterExpressionElement = doc.createElementNS(null,PolicyStrings.PARAMETER_EXPRESSION_EL_NAME);

			Text contextTxtId = doc.createTextNode("ctxWorkingHours");
			Text parameterTxtExpressions = doc.createTextNode(PolicyPublisherTest.testcontext);

			contextIdElement.appendChild(contextTxtId);
			parameterExpressionElement.appendChild(parameterTxtExpressions);

			contextElement.appendChild(contextIdElement);
			contextElement.appendChild(parameterExpressionElement);

			signature2Element.appendChild(contextElement);
		}


		test.appendChild(testTxt);
		//		signature2Element.appendChild(test);

		Helpers.addAdministrativeDomain(signature2Element, signature);

		return signature2Element;
	}

	@Override
	public Class<Signature2> handles() {
		return Signature2.class;
	}

}
