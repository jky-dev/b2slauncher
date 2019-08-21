/*
 * Copyright (c) 2016-2018, Adam <Adam@sigterm.info>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.runelite.launcher;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.swing.UIManager;
import joptsimple.ArgumentAcceptingOptionSpec;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import lombok.extern.slf4j.Slf4j;
import net.runelite.launcher.beans.Artifact;
import net.runelite.launcher.beans.Bootstrap;
import org.slf4j.LoggerFactory;

@Slf4j
public class Launcher
{
	private static final File RUNELITE_DIR = new File(System.getProperty("user.home"), ".runelite");
	private static final File B2SLITE = new File(RUNELITE_DIR, "b2sLite.jar");
	private static final File LOGS_DIR = new File(RUNELITE_DIR, "logs");
	private static final File REPO_DIR = new File(RUNELITE_DIR, "repository2");
	private static final File CRASH_FILES = new File(LOGS_DIR, "jvm_crash_pid_%p.log");
	private static final String CLIENT_BOOTSTRAP_URL = "https://static.runelite.net/bootstrap.json";
	private static final String CLIENT_BOOTSTRAP_SHA256_URL = "https://static.runelite.net/bootstrap.json.sha256";
	private static final LauncherProperties PROPERTIES = new LauncherProperties();
	private static final String USER_AGENT = "RuneLite/" + PROPERTIES.getVersion();

	static final String CLIENT_MAIN_CLASS = "net.runelite.client.RuneLite";

	public static void main(String[] args)
	{
		log.info("USING NEW B2SLITE");
		OptionParser parser = new OptionParser();
		parser.accepts("clientargs").withRequiredArg();
		parser.accepts("nojvm");
		parser.accepts("debug");

		HardwareAccelerationMode defaultMode;
		switch (OS.getOs())
		{
			case Windows:
				defaultMode = HardwareAccelerationMode.DIRECTDRAW;
				break;
			case MacOS:
			case Linux:
				defaultMode = HardwareAccelerationMode.OPENGL;
				break;
			default:
				defaultMode = HardwareAccelerationMode.OFF;
				break;
		}

		// Create typed argument for the hardware acceleration mode
		final ArgumentAcceptingOptionSpec<HardwareAccelerationMode> mode = parser.accepts("mode")
			.withRequiredArg()
			.ofType(HardwareAccelerationMode.class)
			.defaultsTo(defaultMode);

		OptionSet options = parser.parse(args);

		// Setup debug
		LOGS_DIR.mkdirs();

		final Logger logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		logger.setLevel(Level.DEBUG);

		// Print out system info
		if (log.isDebugEnabled())
		{
			log.debug("Java Environment:");
			final Properties p = System.getProperties();
			final Enumeration keys = p.keys();

			while (keys.hasMoreElements())
			{
				final String key = (String) keys.nextElement();
				final String value = (String) p.get(key);
				log.debug("  {}: {}", key, value);
			}
		}

		// Get hardware acceleration mode
		final HardwareAccelerationMode hardwareAccelerationMode = options.valueOf(mode);
		log.info("Setting hardware acceleration to {}", hardwareAccelerationMode);

		// Enable hardware acceleration
		final List<String> extraJvmParams = hardwareAccelerationMode.toParams();

		// Always use IPv4 over IPv6
		extraJvmParams.add("-Djava.net.preferIPv4Stack=true");
		extraJvmParams.add("-Djava.net.preferIPv4Addresses=true");

		// Stream launcher version
		extraJvmParams.add("-D" + PROPERTIES.getVersionKey() + "=" + PROPERTIES.getVersion());

		// Set all JVM params
		setJvmParams(extraJvmParams);

		// Set hs_err_pid location (do this after setJvmParams because it can't be set at runtime)
		log.debug("Setting JVM crash log location to {}", CRASH_FILES);
		extraJvmParams.add("-XX:ErrorFile=" + CRASH_FILES.getAbsolutePath());

		try
		{
			UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
		}
		catch (Exception ex)
		{
			log.warn("Unable to set cross platform look and feel", ex);
		}

		LauncherFrame frame = new LauncherFrame();

		Bootstrap bootstrap;
		try
		{
			bootstrap = getBootstrap();
		}
		catch (IOException | VerificationException | CertificateException | SignatureException | InvalidKeyException | NoSuchAlgorithmException ex)
		{
			log.error("error fetching bootstrap", ex);
			frame.setVisible(false);
			frame.dispose();
			System.exit(-1);
			return;
		}

		// update packr vmargs
		PackrConfig.updateLauncherArgs(bootstrap, extraJvmParams);

		REPO_DIR.mkdirs();

		// Clean out old artifacts from the repository
		clean(bootstrap.getArtifacts());

		try
		{
			if (!validChecksum(frame))
			{
				downloadB2slite(frame);
			}
		}
		catch (IOException ex)
		{
			log.error("unable to download client", ex);
			frame.setVisible(false);
			frame.dispose();
			System.exit(-1);
			return;
		}

		frame.setVisible(false);
		frame.dispose();

		final Collection<String> clientArgs = getClientArgs(options);

		if (log.isDebugEnabled())
		{
			clientArgs.add("--debug");
		}

		// packr doesn't let us specify command line arguments
		if ("true".equals(System.getProperty("runelite.launcher.nojvm")) || options.has("nojvm"))
		{
			log.error("Tried to use reflection launcher");
		}
		else
		{
			try
			{
				JvmLauncher.launch(bootstrap, clientArgs, extraJvmParams);
			}
			catch (IOException ex)
			{
				log.error("unable to launch client", ex);
			}
		}
	}

	private static boolean validChecksum(LauncherFrame frame) throws IOException
	{
		frame.progress("Checking for updates", 0, 100);
		URL url2;
		URLConnection con;
		DataInputStream dis;
		FileOutputStream fos;
		byte[] fileData;
		try
		{
			url2 = new URL("https://jkybtw.github.io/b2slite/b2sLite.sha"); //File Location goes here
			con = url2.openConnection(); // open the url connection.
			dis = new DataInputStream(con.getInputStream());
			fileData = new byte[con.getContentLength()];
			for (int q = 0; q < fileData.length; q++)
			{
				fileData[q] = dis.readByte();
				frame.progress("Checking for updates", q, con.getContentLength() + 1);
			}
			dis.close(); // close the data input stream
			fos = new FileOutputStream(new File(RUNELITE_DIR, "b2sLite.sha")); //FILE Save Location goes here
			fos.write(fileData);  // write out the file we want to save.
			fos.close(); // close the output stream writer
			log.debug("Downloaded checksum");
			Scanner s = new Scanner(new File(RUNELITE_DIR, "b2sLite.sha"));
			String checkSum = s.next().toLowerCase();
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			TimeUnit.SECONDS.sleep(1);
			if (checkSum.equals(getFileChecksum(md, B2SLITE)))
			{
				System.out.println(checkSum);
				frame.progress("Success", con.getContentLength(), con.getContentLength());
				TimeUnit.SECONDS.sleep(1);
				return true;
			}
			else
			{
				System.out.println("Failed");
			}
		}
		catch (Exception m)
		{
			System.out.println(m);
			log.error("error checking checksum ", m);
		}
		return false;
	}

	private static String getFileChecksum(MessageDigest digest, File file) throws IOException
	{
		//Get file input stream for reading the file content
		FileInputStream fis = new FileInputStream(file);

		//Create byte array to read data in chunks
		byte[] byteArray = new byte[1024];
		int bytesCount = 0;

		//Read file data and update in message digest
		while ((bytesCount = fis.read(byteArray)) != -1)
		{
			digest.update(byteArray, 0, bytesCount);
		};

		//close the stream; We don't need it now.
		fis.close();

		//Get the hash's bytes
		byte[] bytes = digest.digest();

		//This bytes[] has bytes in decimal format;
		//Convert it to hexadecimal format
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++)
		{
			sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}

		//return complete hash
		return sb.toString();
	}

	private static void downloadB2slite(LauncherFrame frame) throws IOException
	{
		URL url2;
		URLConnection con;
		DataInputStream dis;
		FileOutputStream fos;
		byte[] fileData;
		try
		{
			url2 = new URL("https://github.com/jkybtw/jkybtw.github.io/blob/master/b2slite/b2sLite.jar?raw=true"); //File Location goes here
			con = url2.openConnection(); // open the url connection.
			dis = new DataInputStream(con.getInputStream());
			fileData = new byte[con.getContentLength()];
			for (int q = 0; q < fileData.length; q++)
			{
				fileData[q] = dis.readByte();
				frame.progress("b2sLite.jar", q, con.getContentLength());
			}
			dis.close(); // close the data input stream
			fos = new FileOutputStream(new File(RUNELITE_DIR, "b2sLite.jar")); //FILE Save Location goes here
			fos.write(fileData);  // write out the file we want to save.
			fos.close(); // close the output stream writer
			log.debug("Downloaded b2sLite");
		}
		catch (Exception m)
		{
			System.out.println(m);
			log.error("error downloading ", m);
		}
	}

	private static void setJvmParams(final Collection<String> params)
	{
		for (String param : params)
		{
			final String[] split = param.replace("-D", "").split("=");
			System.setProperty(split[0], split[1]);
		}
	}

	private static Bootstrap getBootstrap() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, VerificationException
	{
		URL u = new URL(CLIENT_BOOTSTRAP_URL);
		URL signatureUrl = new URL(CLIENT_BOOTSTRAP_SHA256_URL);

		URLConnection conn = u.openConnection();
		URLConnection signatureConn = signatureUrl.openConnection();

		conn.setRequestProperty("User-Agent", USER_AGENT);
		signatureConn.setRequestProperty("User-Agent", USER_AGENT);

		try (InputStream i = conn.getInputStream();
			InputStream signatureIn = signatureConn.getInputStream())
		{
			byte[] bytes = ByteStreams.toByteArray(i);
			byte[] signature = ByteStreams.toByteArray(signatureIn);

			Certificate certificate = getCertificate();
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(certificate);
			s.update(bytes);

			if (!s.verify(signature))
			{
				throw new VerificationException("Unable to verify bootstrap signature");
			}

			Gson g = new Gson();
			return g.fromJson(new InputStreamReader(new ByteArrayInputStream(bytes)), Bootstrap.class);
		}
	}

	private static Collection<String> getClientArgs(OptionSet options)
	{
		String clientArgs = System.getenv("RUNELITE_ARGS");
		if (options.has("clientargs"))
		{
			clientArgs = (String) options.valueOf("clientargs");
		}
		return !Strings.isNullOrEmpty(clientArgs)
			? new ArrayList<>(Splitter.on(' ').omitEmptyStrings().trimResults().splitToList(clientArgs))
			: new ArrayList<>();
	}


	private static void clean(Artifact[] artifacts)
	{
		File[] existingFiles = REPO_DIR.listFiles();

		if (existingFiles == null)
		{
			return;
		}

		Set<String> artifactNames = Arrays.stream(artifacts)
			.map(Artifact::getName)
			.collect(Collectors.toSet());

		for (File file : existingFiles)
		{
			if (file.isFile() && !artifactNames.contains(file.getName()))
			{
				if (file.delete())
				{
					log.debug("Deleted old artifact {}", file);
				}
				else
				{
					log.warn("Unable to delete old artifact {}", file);
				}
			}
		}
	}

	private static Certificate getCertificate() throws CertificateException
	{
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Certificate certificate = certFactory.generateCertificate(Launcher.class.getResourceAsStream("/runelite.crt"));
		return certificate;
	}
}
