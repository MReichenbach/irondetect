package de.hshannover.f4.trust.irondetect.policy.publisher;

import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.config.BasicAuthConfig;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.InitializationException;
import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.log.IfmapJLog;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishRequest;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Signature;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.handler.SignatureHandler;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.metadata.PolicyMetadataFactory;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature2;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature2Handler;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature3;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature3Handler;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature5;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature5Handler;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature6;
import de.hshannover.f4.trust.irondetect.policy.publisher.test.Signature6Handler;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings;

public class PolicyPublisherTest {

	private static List<PublishUpdate> mPublishUpdates = new ArrayList<PublishUpdate>();

	private static PolicyMetadataFactory mMetadataFactory = new PolicyMetadataFactory();

	private static DocumentBuilder mDocumentBuilder;

	public static String testcontext = "&quot;DATETIME&quot; &gt; &quot;06:00&quot; and &quot;DATETIME&quot; &lt; &quot;22:00&quot;";

	private static String testSignature = "\"smartphone.android.app.permission.granted\" =! \"android.permission.RECEIVE_BOOT_COMPLETED\" and \"smartphone.android.app.permission.granted\" = \"android.permission.CAMERA\" and \"smartphone.android.app.permission.granted\" = \"android.permission.INTERNET\" ctxWorkingHours";

	public static void main(String[] args) throws IfmapErrorResult, IfmapException {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			mDocumentBuilder = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			IfmapJLog.error("Could not get DocumentBuilder instance [" + e.getMessage() + "]");
			throw new RuntimeException(e);
		}


		Identifiers.registerIdentifierHandler(new SignatureHandler());
		Identifiers.registerIdentifierHandler(new Signature2Handler());
		Identifiers.registerIdentifierHandler(new Signature3Handler());
		Identifiers.registerIdentifierHandler(new Signature5Handler());
		Identifiers.registerIdentifierHandler(new Signature6Handler());

		PublishUpdate update = Requests.createPublishUpdate();
		PublishUpdate update2 = Requests.createPublishUpdate();
		PublishUpdate update3 = Requests.createPublishUpdate();
		PublishUpdate update5 = Requests.createPublishUpdate();
		PublishUpdate update6 = Requests.createPublishUpdate();

		Document hasElementMetadata = mMetadataFactory.createHasElement();
		Signature signature = new Signature("sigSuspiciousApp", "irondetect-DEV");
		signature
				.addFeatureExpression("&quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.RECEIVE_BOOT_COMPLETED&quot;");
		signature
				.addFeatureExpression("and &quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.CAMERA&quot;");
		signature
				.addFeatureExpression("and &quot;smartphone.android.app.permission.granted&quot; = &quot;android.permission.INTERNET&quot;");
		signature.addContext("ctxWorkingHours", "&quot;DATETIME&quot; &gt; &quot;06:00&quot;");
		signature.addContext("ctxWorkingHours", "and &quot;DATETIME&quot; &lt; &quot;22:00&quot;");

		Signature2 signature2 = new Signature2("sigSuspiciousApp", testSignature, "irondetect-DEV");
		Signature3 signature3 = new Signature3("sigSuspiciousApp", testSignature, "irondetect-DEV");
		Signature5 signature5 = new Signature5("sigSuspiciousApp", testSignature, "irondetect-DEV");
		Signature6 signature6 = new Signature6("sigSuspiciousApp", testSignature, "irondetect-DEV");

		Device device = Identifiers.createDev("freeradius-pdp");

		update.setIdentifier1(signature);
		update.setIdentifier2(device);
		update.addMetadata(hasElementMetadata);
		update.setLifeTime(MetadataLifetime.forever);

		mPublishUpdates.add(update);

		update2.setIdentifier1(signature2);
		update2.setIdentifier2(device);
		update2.addMetadata(hasElementMetadata);
		update2.setLifeTime(MetadataLifetime.forever);

		mPublishUpdates.add(update2);

		update3.setIdentifier1(signature3);
		update3.setIdentifier2(device);
		update3.addMetadata(hasElementMetadata);
		update3.setLifeTime(MetadataLifetime.forever);

		mPublishUpdates.add(update3);

		update5.setIdentifier1(signature5);
		update5.setIdentifier2(device);
		update5.addMetadata(hasElementMetadata);
		update5.setLifeTime(MetadataLifetime.forever);

		mPublishUpdates.add(update5);

		update6.setIdentifier1(signature6);
		update6.setIdentifier2(device);
		update6.addMetadata(hasElementMetadata);
		update6.setLifeTime(MetadataLifetime.forever);

		mPublishUpdates.add(update6);

		SSRC ssrc = createSSRC();
		ssrc.newSession();

		PublishRequest req = Requests.createPublishReq();

		for (PublishUpdate u : mPublishUpdates) {
			req.addPublishElement(u);
		}

		ssrc.publish(req);
		ssrc.endSession();


	}

	private static SSRC createSSRC() throws InitializationException {
		boolean threadSafe = true;
		int initialConnectionTimeout = 120 * 1000;
		BasicAuthConfig config = new BasicAuthConfig(
				PolicyStrings.DEFAULT_URL,
				PolicyStrings.DEFAULT_USER,
				PolicyStrings.DEFAULT_PASS,
				PolicyStrings.DEFAULT_KEYSTORE_PATH,
				PolicyStrings.DEFAULT_KEYSTORE_PASS,
				threadSafe,
				initialConnectionTimeout);
		SSRC ssrc = IfmapJ.createSsrc(config);

		return ssrc;
	}

}
