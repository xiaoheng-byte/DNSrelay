import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Check {

	Map<String, String> ipTable = new HashMap<String, String>();

	public void readData(String path) throws IOException {
		File inFile = new File(path);
		String inString = null;
		BufferedReader reader = new BufferedReader(new FileReader(inFile));
		System.out.println("------------------------------------");
		System.out.println("ipDomainName\t|ipAddress");
		while ((inString = reader.readLine()) != null) {
			String[] ip = inString.split(" ");
			String ipAddress = ip[0];
			String ipDomainName = ip[1];
			ipTable.put(ipDomainName, ipAddress);
			System.out.println(ipDomainName + "\t|" + ipAddress);
		}
		System.out.println("------------------------------------");
		reader.close();
	}
}
