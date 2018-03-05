
package es.bde.aps.jbs.module;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.jboss.security.plugins.ClassLoaderLocator;
import org.jboss.security.plugins.ClassLoaderLocatorFactory;

/**
 * Privileged Blocks
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Sep 26, 2007
 * @version $Revision$
 */
class SecurityActions {
	static ClassLoader getContextClassLoader() {
		return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
			public ClassLoader run() {
				return Thread.currentThread().getContextClassLoader();
			}
		});
	}

	static Void setContextClassLoader(final ClassLoader cl) {
		return AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Thread.currentThread().setContextClassLoader(cl);
				return null;
			}
		});
	}

	static URL findResource(final URLClassLoader cl, final String name) {
		return AccessController.doPrivileged(new PrivilegedAction<URL>() {
			public URL run() {
				return cl.findResource(name);
			}
		});
	}

	static InputStream openStream(final URL url) throws PrivilegedActionException {
		return AccessController.doPrivileged(new PrivilegedExceptionAction<InputStream>() {
			public InputStream run() throws IOException {
				return url.openStream();
			}
		});
	}

	static Class<?> loadClass(final String name, final String jbossModuleName) throws PrivilegedActionException {
		return AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>() {
			public Class<?> run() throws ClassNotFoundException {
				ClassLoader moduleCL = null;
				if (jbossModuleName != null && jbossModuleName.length() > 0) {
					ClassLoaderLocator locator = ClassLoaderLocatorFactory.get();
					if (locator != null)
						moduleCL = locator.get(jbossModuleName);
				}
				ClassLoader[] cls = new ClassLoader[] { getContextClassLoader(), // User defined classes
						moduleCL, // user defined module class loader
						SecurityActions.class.getClassLoader(), // PB classes (not always on TCCL [modular env])
						ClassLoader.getSystemClassLoader() }; // System loader, usually has app class path

				ClassNotFoundException e = null;
				for (ClassLoader cl : cls) {
					if (cl == null)
						continue;

					try {
						return cl.loadClass(name);
					} catch (ClassNotFoundException ce) {
						e = ce;
					}
				}
				throw e != null ? e : new ClassNotFoundException(name);
			}
		});
	}

	static Class<?> loadClass(final String name) throws PrivilegedActionException {
		return loadClass(name, null);
	}
}