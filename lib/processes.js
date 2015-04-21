
import { exec } from "child_process";

function getProcessList(callback) {
  
  exec('ps aux', function(err, stdout, stderr) {

    if(err) {
      console.error("Error fetching process list:", err);
      return callback(err);
    }

    let tmp = stdout.split('\n');

    const headers = tmp.shift().split(/\s+/);

    let rows = tmp.map(function(row) {
      let fields = row.split(/\s+/);
      let out = {};
      fields.forEach(function(value, index) {
        let header = headers[index];
        if(!header) {
          out[headers[headers.length-1]] += " " + value;
          return;
        }
        out[headers[index]] = value;
      });
      return out;
    });

    return callback(null, rows);

  });

}

export default getProcessList;