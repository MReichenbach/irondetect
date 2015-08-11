package de.hshannover.f4.trust.irondetect.util;

import de.hshannover.f4.trust.ifmapj.messages.PollResult;

/**
 * 
 * @author Marcel Reichenbach
 *
 */
public interface PollResultSender {
	/**
	 * Adds a new {@link PollResultReceiver} to this {@link PollResultSender}. {@link PollResultSender} will be informed
	 * all {@link PollResultReceiver}s were becomes a new {@link PollResult}.
	 * 
	 * @param prReceiver the new {@link PollResultReceiver} to add to the{@link PollResultSender}
	 */
	public void addPollResultReceiver(PollResultReceiver prReceiver);
}
