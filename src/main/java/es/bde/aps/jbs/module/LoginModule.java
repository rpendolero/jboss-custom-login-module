package es.bde.aps.jbs.module;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.acl.Group;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.jboss.security.PicketBoxLogger;
import org.jboss.security.PicketBoxMessages;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

/**
 * This class have the objetive manage the login of users to Ldap server and
 * getting the list of groups from a database.
 * 
 * @author rpendolero
 * 
 */
public class LoginModule extends UsernamePasswordLoginModule {

	private static final String PRINCIPAL_DN_PREFIX_OPT = "principalDNPrefix";
	private static final String PRINCIPAL_DN_SUFFIX_OPT = "principalDNSuffix";
	private static final String DS_JNDI_NAME = "dsJndiName";
	private static final String ROLES_QUERY = "rolesQuery";
	private static final String USERS_PROPERTIES = "application-users.properties";
	private static final String ROLES_PROPERTIES = "application-roles.properties";

	private static final String[] ALL_VALID_OPTIONS = {

			//
			DS_JNDI_NAME,
			//
			ROLES_QUERY,
			//
			PRINCIPAL_DN_PREFIX_OPT,
			//
			PRINCIPAL_DN_SUFFIX_OPT,
			//
			Context.INITIAL_CONTEXT_FACTORY,
			//
			Context.PROVIDER_URL,
			//
			Context.SECURITY_PROTOCOL,
			//
			Context.SECURITY_AUTHENTICATION };

	private static final String USER_ADMIN = "admin";
	private static final String CHAR_SEPARATOR = ",";

	/** The JNDI name of the DataSource to use */
	protected String dsJndiName;
	/** The sql query to obtain the user roles */
	protected String rolesQuery;
	/** Whether to suspend resume transactions during database operations */
	protected boolean suspendResume = true;
	/** The JNDI name of the transaction manager */
	protected String txManagerJndiName = "java:/TransactionManager";
	/** Logger */
	private Logger logger = Logger.getLogger(getClass());
	private String factoryName;
	private String providerURL;
	private String authType;
	private Properties users;
	private Properties roles;

	/**
	 * Constructor
	 */
	public LoginModule() {

	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		logger.debug("Initializing login module [" + getClass().getSimpleName() + "]...");
		addValidOptions(ALL_VALID_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);
		try {
			loadUsersLocal();
			loadRolesLocal();
		} catch (IOException e) {
			e.printStackTrace();
		}

		loadOptions();
	}

	/**
	 * @throws IOException
	 */
	private void loadRolesLocal() throws IOException {
		roles = loadProperties(ROLES_PROPERTIES);
	}

	/**
	 * @throws IOException
	 */
	private void loadUsersLocal() throws IOException {
		users = loadProperties(USERS_PROPERTIES);

	}

	/**
	 * 
	 * @param propertiesName
	 *            - the name of the properties file resource
	 * @return the loaded properties file if found
	 * @exception java.io.IOException
	 *                thrown if the properties file cannot be found or loaded
	 */
	private Properties loadProperties(String propertiesName) throws IOException {
		Properties bundle = null;
		ClassLoader loader = SecurityActions.getContextClassLoader();
		URL url = null;
		// First check for local visibility via a URLClassLoader.findResource
		if (loader instanceof URLClassLoader) {
			logger.debug("");
			URLClassLoader ucl = (URLClassLoader) loader;
			url = SecurityActions.findResource(ucl, propertiesName);
			PicketBoxLogger.LOGGER.traceAttemptToLoadResource(propertiesName);
		}
		// Do a general resource search
		if (url == null) {
			url = loader.getResource(propertiesName);
			if (url == null) {
				try {
					url = new URL(propertiesName);
				} catch (MalformedURLException mue) {
					PicketBoxLogger.LOGGER.debugFailureToOpenPropertiesFromURL(mue);
					File tmp = new File(propertiesName);
					if (tmp.exists())
						url = tmp.toURI().toURL();
				}
			}
		}
		if (url == null) {
			throw PicketBoxMessages.MESSAGES.unableToFindPropertiesFile(propertiesName);
		}

		Properties defaults = new Properties();
		bundle = new Properties(defaults);
		if (url != null) {
			InputStream is = null;
			try {
				is = SecurityActions.openStream(url);
			} catch (PrivilegedActionException e) {
				throw new IOException(e.getLocalizedMessage());
			}
			if (is != null) {
				try {
					bundle.load(is);
				} finally {
					safeClose(is);
				}
			} else {
				throw PicketBoxMessages.MESSAGES.unableToLoadPropertiesFile(propertiesName);
			}
			PicketBoxLogger.LOGGER.tracePropertiesFileLoaded(propertiesName, bundle.keySet());
		}

		return bundle;
	}

	/**
	 * Method that load the options configuration
	 */
	private void loadOptions() {
		logger.debug("Loading options of login module [" + getClass().getSimpleName() + "]...");
		dsJndiName = (String) options.get(DS_JNDI_NAME);
		if (dsJndiName == null)
			dsJndiName = "java:/DefaultDS";
		logger.debug("Option jndi name loaded [" + dsJndiName + "]");

		rolesQuery = (String) options.get(ROLES_QUERY);
		logger.debug("Option principals query loaded [" + rolesQuery + "]");

		factoryName = (String) options.get(Context.INITIAL_CONTEXT_FACTORY);
		if (factoryName == null) {
			factoryName = "com.sun.jndi.ldap.LdapCtxFactory";
		}
		logger.debug("Option factory name  [" + factoryName + "]");

		providerURL = (String) options.get(Context.PROVIDER_URL);
		if (providerURL == null) {
			String protocol = (String) options.get(Context.SECURITY_PROTOCOL);
			providerURL = "ldap://localhost:" + ((protocol != null && protocol.equals("ssl")) ? "636" : "389");
		}
		logger.debug("Option provide URL [" + providerURL + "]");

		authType = (String) options.get(Context.SECURITY_AUTHENTICATION);
		if (authType == null) {
			authType = "simple";
		}
	}

	@Override
	protected String getUsersPassword() throws LoginException {
		String username = getUsername();
		String password = null;
		if (username != null)
			password = users.getProperty(username, null);
		return password;
	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		Group[] roleSets = null;
		if (loginOk) {
			String username = getUsername();
			if (USER_ADMIN.equals(username)) {
				return getRolesLocal(username);
			} else {
				return getRolesDataBase(username);
			}
		}

		return roleSets;

	}

	/**
	 * 
	 * @param username
	 * @return
	 * @throws LoginException
	 */
	private Group[] getRolesDataBase(String username) throws LoginException {
		logger.debug("Getting roles for user [" + username + "] ...");

		Group[] roleSets = null;
		if (rolesQuery != null) {

			Connection conn = null;

			PreparedStatement ps = null;
			ResultSet rs = null;
			try {
				conn = getConnection(dsJndiName);

				// Get the user role names
				PicketBoxLogger.LOGGER.traceExecuteQuery(rolesQuery, username);
				ps = conn.prepareStatement(rolesQuery);
				ps.setString(1, username);

				rs = ps.executeQuery();
				roleSets = getRolesResultSet(username, rs);

			} catch (Exception ex) {
				LoginException le = new LoginException(PicketBoxMessages.MESSAGES.failedToProcessQueryMessage());
				le.initCause(ex);
				logger.error("Error getting roles for user [" + username + "] [" + ex.getMessage() + "]");
				throw le;
			} finally {
				try {
					if (rs != null) {
						rs.close();
					}
					if (ps != null) {
						ps.close();
					}
					if (conn != null) {
						conn.close();
					}

				} catch (SQLException e) {
				}

			}

		}
		logger.debug("Getted roles for user [" + username + "].");
		return roleSets;
	}

	/**
	 * 
	 * @return
	 */
	private Group[] getRolesLocal(String targetUser) {
		Enumeration<?> users = roles.propertyNames();
		SimpleGroup rolesGroup = new SimpleGroup("Roles");
		List<Group> groups = new ArrayList<Group>();
		groups.add(rolesGroup);
		while (users.hasMoreElements() && targetUser != null) {
			String user = (String) users.nextElement();
			String value = roles.getProperty(user);
			String[] rolesNames = value.split(CHAR_SEPARATOR);
			for (String roleName : rolesNames) {
				rolesGroup = new SimpleGroup(roleName);
				groups.add(rolesGroup);
			}
		}

		Group[] roleSets = new Group[groups.size()];
		groups.toArray(roleSets);
		return roleSets;
	}

	/**
	 * Method that get roles from database.
	 * 
	 * @param username
	 * 
	 * @param rs
	 * @return
	 * @throws SQLException
	 */
	private Group[] getRolesResultSet(String username, ResultSet rs) throws SQLException {
		HashMap<String, Group> setsMap = new HashMap<String, Group>();
		Group[] roleSets;
		roleSets = new Group[] { new SimpleGroup("Roles") };
		if (rs.next() == false) {
			return roleSets;
		}

		do {
			String groupName = rs.getString(1);
			Group group = (Group) setsMap.get(groupName);
			if (group == null) {
				SimplePrincipal role = new SimplePrincipal(groupName);
				roleSets[0].addMember(role);
			}

			try {
				Principal p = createIdentity(username);
				group.addMember(p);
			} catch (Exception e) {
				PicketBoxLogger.LOGGER.debugFailureToCreatePrincipal(username, e);
			}
			logger.debug("Getted role [" + groupName + "] to user [" + username + "]  ...");
		} while (rs.next());

		// roleSets = new Group[setsMap.size()];
		return roleSets;

	}

	/**
	 * Method that get a connection to base data.
	 * 
	 * @param dsJndiName
	 * @return
	 * @throws LoginException
	 */
	private Connection getConnection(String dsJndiName) throws LoginException {
		Connection connection;
		try {
			logger.debug("Creating connection with jndi name [" + dsJndiName + "]  ...");
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(dsJndiName);
			connection = ds.getConnection();
			logger.debug("Created connection with jndi name [" + dsJndiName + "].");

		} catch (NamingException ex) {
			LoginException le = new LoginException(PicketBoxMessages.MESSAGES.failedToLookupDataSourceMessage(dsJndiName));
			le.initCause(ex);
			throw le;
		} catch (SQLException ex) {
			LoginException le = new LoginException(PicketBoxMessages.MESSAGES.failedToProcessQueryMessage());
			le.initCause(ex);
			throw le;
		}
		return connection;
	}

	@Override
	protected boolean validatePassword(String inputPassword, String expectedPassword) {
		boolean isValid = false;
		String username = getUsername();
		logger.debug("Validating password to user [" + username + "]...");
		if (inputPassword != null) {
			if ("admin".equals(username)) {
				return (inputPassword.equals(expectedPassword));
			} else {
				try {
					createLdapInitContext(username, inputPassword);
					logger.debug("Validated correctly password to user [" + username + "].");
					isValid = true;
				} catch (Throwable e) {
					logger.error("Error when validating user [" + username + "] [" + e.getMessage() + "]");
					super.setValidateError(e);
				}
			}

		} else {
			logger.debug("Password is null to user [" + username + "]");
		}

		return isValid;
	}

	/**
	 * Method that create Ldap initial context
	 * 
	 * @param username
	 * @param inputPassword
	 * @return
	 * @throws NamingException
	 */
	private InitialLdapContext createLdapInitContext(String username, String inputPassword) throws NamingException {
		logger.debug("Creating context to user [" + username + "]...");
		Properties env = new Properties();
		// Set defaults for key values if they are missing

		env.setProperty(Context.INITIAL_CONTEXT_FACTORY, factoryName);
		env.setProperty(Context.SECURITY_AUTHENTICATION, authType);

		String userDN = createUserDN(username);
		logger.debug("Connecting to url [" + providerURL + "] with [" + userDN + "]...");

		env.setProperty(Context.PROVIDER_URL, providerURL);
		env.setProperty(Context.SECURITY_PRINCIPAL, userDN);
		env.put(Context.SECURITY_CREDENTIALS, inputPassword);

		InitialLdapContext ctx = new InitialLdapContext(env, null);
		logger.debug("Created context to user [" + username + "].");
		return ctx;
	}

	/**
	 * Method that create of distingue name of an user.
	 * 
	 * @param username
	 * @return
	 */
	private String createUserDN(String username) {
		String principalDNPrefix = (String) options.get(PRINCIPAL_DN_PREFIX_OPT);
		if (principalDNPrefix == null)
			principalDNPrefix = "";
		String principalDNSuffix = (String) options.get(PRINCIPAL_DN_SUFFIX_OPT);
		if (principalDNSuffix == null)
			principalDNSuffix = "";
		StringBuilder builder = new StringBuilder(principalDNPrefix);
		builder.append(username).append(principalDNSuffix);
		return builder.toString();
	}
}
