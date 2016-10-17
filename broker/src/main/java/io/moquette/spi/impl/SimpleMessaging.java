/*
 * Copyright (c) 2012-2015 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */
package io.moquette.spi.impl;

import com.lmax.disruptor.EventFactory;
import com.lmax.disruptor.EventHandler;
import io.moquette.BrokerConstants;
import io.moquette.spi.IMessagesStore;
import io.moquette.interception.InterceptHandler;
import io.moquette.proto.messages.AbstractMessage;
import io.moquette.server.ServerChannel;
import io.moquette.server.config.IConfig;
import io.moquette.server.netty.NettyMQTTHandler;
import io.moquette.spi.ISessionsStore;
import io.moquette.spi.impl.security.*;
import io.moquette.spi.impl.subscriptions.Subscription;
import io.moquette.spi.impl.subscriptions.SubscriptionsStore;
import io.moquette.spi.persistence.MapDBPersistentStore;
import io.moquette.spi.security.IAuthenticator;
import io.moquette.spi.security.IAuthorizator;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import lus.LusXF;

/**
 *
 * Singleton class that orchestrate the execution of the protocol.
 *
 * It's main responsibility is instantiate the ProtocolProcessor.
 *
 * @author andrea
 */
public class SimpleMessaging implements EventHandler<SimpleMessaging.ValueEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(SimpleMessaging.class);

    private SubscriptionsStore subscriptions;

    private MapDBPersistentStore m_mapStorage;

    private BrokerInterceptor m_interceptor;

    private static SimpleMessaging INSTANCE;
    
    private final ProtocolProcessor m_processor = new ProtocolProcessor();

    private SimpleMessaging() {
    }

    public static SimpleMessaging getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SimpleMessaging();
        }
        return INSTANCE;
    }

    /**
     * Initialize the processing part of the broker.
     * @param props the properties carrier where some props like port end host could be loaded.
     *              For the full list check of configurable properties check moquette.conf file.
     * @param embeddedObservers a list of callbacks to be notified of certain events inside the broker.
     *                          Could be empty list of null.
     * @param authenticator an implementation of the authenticator to be used, if null load that specified in config
     *                      and fallback on the default one (permit all).
     * @param authorizator an implementation of the authorizator to be used, if null load that specified in config
     *                      and fallback on the default one (permit all).
     * */
    public ProtocolProcessor init(IConfig props, List<? extends InterceptHandler> embeddedObservers,
                                  IAuthenticator authenticator, IAuthorizator authorizator) {
        subscriptions = new SubscriptionsStore();

        m_mapStorage = new MapDBPersistentStore(props);
        m_mapStorage.initStore();
        IMessagesStore messagesStore = m_mapStorage.messagesStore();
        ISessionsStore sessionsStore = m_mapStorage.sessionsStore(messagesStore);

        List<InterceptHandler> observers = new ArrayList<>(embeddedObservers);
        String interceptorClassName = props.getProperty("intercept.handler");
        if (interceptorClassName != null && !interceptorClassName.isEmpty()) {
            try {
                InterceptHandler handler = Class.forName(interceptorClassName).asSubclass(InterceptHandler.class).newInstance();
                observers.add(handler);
            } catch (Throwable ex) {
                LOG.error("Can't load the intercept handler {}", ex);
            }
        }
        m_interceptor = new BrokerInterceptor(observers);

        subscriptions.init(sessionsStore);

        String configPath = System.getProperty("moquette.path", null);
        String authenticatorClassName = props.getProperty(BrokerConstants.AUTHENTICATOR_CLASS_NAME, "");

        if (!authenticatorClassName.isEmpty()) {
            authenticator = (IAuthenticator)loadClass(authenticatorClassName, IAuthenticator.class);
            LOG.info("Loaded custom authenticator {}", authenticatorClassName);
        }

        if (authenticator == null) {
            String passwdPath = props.getProperty(BrokerConstants.PASSWORD_FILE_PROPERTY_NAME, "");
            if (passwdPath.isEmpty()) {
                authenticator = new AcceptAllAuthenticator();
            } else {
                authenticator = new FileAuthenticator(configPath, passwdPath);
            }
        }

        String authorizatorClassName = props.getProperty(BrokerConstants.AUTHORIZATOR_CLASS_NAME, "");
        if (!authorizatorClassName.isEmpty()) {
            authorizator = (IAuthorizator)loadClass(authorizatorClassName, IAuthorizator.class);
            LOG.info("Loaded custom authorizator {}", authorizatorClassName);
        }

        if (authorizator == null) {
            String aclFilePath = props.getProperty(BrokerConstants.ACL_FILE_PROPERTY_NAME, "");
            if (aclFilePath != null && !aclFilePath.isEmpty()) {
                authorizator = new DenyAllAuthorizator();
                File aclFile = new File(configPath, aclFilePath);
                try {
                    authorizator = ACLFileParser.parse(aclFile);
                } catch (ParseException pex) {
                    LOG.error(String.format("Format error in parsing acl file %s", aclFile), pex);
                }
                LOG.info("Using acl file defined at path {}", aclFilePath);
            } else {
                authorizator = new PermitAllAuthorizator();
                LOG.info("Starting without ACL definition");
            }

        }

        boolean allowAnonymous = Boolean.parseBoolean(props.getProperty(BrokerConstants.ALLOW_ANONYMOUS_PROPERTY_NAME, "true"));
        m_processor.init(subscriptions, messagesStore, sessionsStore, authenticator, allowAnonymous, authorizator, m_interceptor);
        return m_processor;
    }
    
    private Object loadClass(String className, Class<?> cls) {
        Object instance = null;
        try {
            Class<?> clazz = Class.forName(className);

            // check if method getInstance exists
            Method method = clazz.getMethod("getInstance", new Class[] {});
            try {
                instance = method.invoke(null, new Object[] {});
            } catch (IllegalArgumentException | InvocationTargetException | IllegalAccessException ex) {
                LOG.error(null, ex);
                throw new RuntimeException("Cannot call method "+ className +".getInstance", ex);
            }
        }
        catch (NoSuchMethodException nsmex) {
            try {
                instance = this.getClass().getClassLoader()
                        .loadClass(className)
                        .asSubclass(cls)
                        .newInstance();
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
                LOG.error(null, ex);
                throw new RuntimeException("Cannot load custom authenticator class " + className, ex);
            }
        } catch (ClassNotFoundException ex) {
            LOG.error(null, ex);
            throw new RuntimeException("Class " + className + " not found", ex);
        } catch (SecurityException ex) {
            LOG.error(null, ex);
            throw new RuntimeException("Cannot call method "+ className +".getInstance", ex);
        }

        return instance;
    }
	
	static abstract class MessagingEvent {
		
	}
	
	static class ValueEvent {
		public MessagingEvent m_event;
		public final static EventFactory<ValueEvent> EVENT_FACTORY = new EventFactory<ValueEvent>() {
			public ValueEvent newInstance() {
				return new ValueEvent();
			}
		};
	}
	
	static class LostConnectionEvent extends MessagingEvent {
		public String clientID;
	}
	
	static class OutputMessagingEvent extends MessagingEvent {
		public ServerChannel m_channel;
		public AbstractMessage m_message;
	}
	
	static class ProtocolEvent extends MessagingEvent {
		public ChannelHandlerContext ctx; // extracted out of public ServerChannel m_session; by a transformation
		public AbstractMessage message;
	}
	
	static class PubAckEvent extends MessagingEvent {
		public int m_messageId;
		public String m_clientID;
	}
	
	static class PublishEvent extends MessagingEvent {
		public String m_topic;
		public AbstractMessage.QOSType m_qos;
		public ByteBuffer m_message;
		public boolean m_retain;
		public String m_clientID;
		public Integer m_msgID;
	}
	
	static class StopEvent extends MessagingEvent { }
	
	static class SubscribeEvent extends MessagingEvent {
		public Subscription m_subscription;
		public int m_messageID;
	}
	
	static class RepublishEvent extends MessagingEvent {
		public String m_clientID;
	}
	
	private NettyMQTTHandler nettyMQTTHandler; // the one and only instance in v0.8
	
	@Override
    public void onEvent(ValueEvent event, long l, boolean bln) throws Exception {
		LusXF.ASSERT(event.m_event instanceof ProtocolEvent);
		ProtocolEvent protocolEvent = ((ProtocolEvent)event.m_event);
		nettyMQTTHandler.channelRead(protocolEvent.ctx, (Object)protocolEvent.message);
    }

    public void shutdown() {
        this.m_mapStorage.close();
    }
}
