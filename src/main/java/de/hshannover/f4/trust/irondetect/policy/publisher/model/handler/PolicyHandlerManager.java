package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import de.hshannover.f4.trust.irondetect.model.PolicyData;

public class PolicyHandlerManager {

	private static final String POST_CLASS_PATH = "de.hshannover.f4.trust.irondetect.policy.publisher.model.handler.";
	
	public static PolicyHandler<?> getHandlerFor(PolicyData data) throws ClassNotFoundException,
			InstantiationException, IllegalAccessException {

		Class<?> handlerClazz = Class.forName(POST_CLASS_PATH + "Policy" + data.getClass().getSimpleName() + "Handler");

		PolicyHandler<?> eventHandler = (PolicyHandler<?>) handlerClazz.newInstance();

		return eventHandler;
	}

}