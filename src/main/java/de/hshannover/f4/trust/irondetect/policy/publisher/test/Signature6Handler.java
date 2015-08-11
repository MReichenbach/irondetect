package de.hshannover.f4.trust.irondetect.policy.publisher.test;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers.Helpers;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler.ExtendetIdentifierHandler;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class Signature6Handler extends ExtendetIdentifierHandler<Signature6> {

	@Override
	public Element toExtendetElement(Identifier identifier, Document doc) throws MarshalException {
		Helpers.checkIdentifierType(identifier, this);

		Signature6 signature = (Signature6) identifier;
		String id = signature.getID();
		String expressions = signature.getFeatureExpressions();

		if (id == null) {
			throw new MarshalException("No id set");
		}

		if (expressions == null) {
			throw new MarshalException("Identity with null featureExpressions not allowed");
		}

		Element signature6Element = doc.createElementNS(PolicyStrings.POLICY_IDENTIFIER_NS_URI,PolicyStrings.SIGNATURE_EL_NAME+6);
		Element idElement = doc.createElementNS(null,PolicyStrings.ID_EL_NAME);
		Element featureExpressionElement1 = buildFeatureExpressionElement("&quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.RECEIVE_BOOT_COMPLETED&quot;",doc);
		Element featureExpressionElement2 = buildFeatureExpressionElement("and &quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.CAMERA&quot;",doc);
		Element featureExpressionElement3 = buildFeatureExpressionElement("and &quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.INTERNET&quot;",doc);
		Element parameterExpressionElement1 = buildparameterExpression("&quot;DATETIME&quot; &gt; &quot;06:00&quot;", doc);
		Element parameterExpressionElement2 = buildparameterExpression("and &quot;DATETIME&quot; &lt; &quot;22:00&quot;", doc);
		Element contextElement = buildContextElement("ctxWorkingHours", doc, parameterExpressionElement1, parameterExpressionElement2);

		Text signatureTxtId = doc.createTextNode(id);

		idElement.appendChild(signatureTxtId);

		signature6Element.appendChild(idElement);
		signature6Element.appendChild(featureExpressionElement1);
		signature6Element.appendChild(featureExpressionElement2);
		signature6Element.appendChild(featureExpressionElement3);
		signature6Element.appendChild(contextElement);

		Helpers.addAdministrativeDomain(signature6Element, signature);

		return signature6Element;
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

	@Override
	public Class<Signature6> handles() {
		return Signature6.class;
	}

}
