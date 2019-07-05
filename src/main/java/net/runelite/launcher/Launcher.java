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

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Launcher
{
	private static final File RUNELITE_DIR = new File(System.getProperty("user.home"), ".runelite");
	private static final File B2SLITE = new File(RUNELITE_DIR, "b2sLite.jar");

	public static void main(String[] args)
	{
		LauncherFrame frame = new LauncherFrame();

		try
		{
			if (!validChecksum(frame)) download(frame);
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

		String javaExePath;
		try
		{
			javaExePath = getJava();
		}
		catch (FileNotFoundException ex)
		{
			log.error("Unable to find java executable", ex);
			return;
		}

		try
		{
			log.debug("starting");
			ProcessBuilder pb = new ProcessBuilder(javaExePath, "-jar", B2SLITE.getAbsolutePath());
			Process p = pb.start();
		}
		catch (Exception e)
		{
			log.error(e.toString());
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
		}
		return false;
	}

	private static void download(LauncherFrame frame) throws IOException
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
		}
	}

	private static String getJava() throws FileNotFoundException
	{
		Path javaHome = Paths.get(System.getProperty("java.home"));

		if (!Files.exists(javaHome))
		{
			throw new FileNotFoundException("JAVA_HOME is not set correctly! directory \"" + javaHome + "\" does not exist.");
		}

		Path javaPath = Paths.get(javaHome.toString(), "bin", "java.exe");

		if (!Files.exists(javaPath))
		{
			javaPath = Paths.get(javaHome.toString(), "bin", "java");
		}

		if (!Files.exists(javaPath))
		{
			throw new FileNotFoundException("java executable not found in directory \"" + javaPath.getParent() + "\"");
		}

		return javaPath.toAbsolutePath().toString();
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
}
