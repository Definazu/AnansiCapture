<script lang="ts">
  import '../../styles/mainPageStyles.css';
  const packets = [
    { no: 2015, time: '0.575/00164', source: '0.701/336.77', destination: '192.168.0.03', protocol: 'TCP/CD' , length: '1240', info:' dkwfjekwekvweivnweivnwenvwnwejnewjf'},
    { no: 2020, time: '0.576/00267', source: '0.705/336.77', destination: '192.168.0.03', protocol: 'TCP', length: '1240', info:' dkwffeeferfergerwejnewjf'},
    
  ];
</script>
<div class="table-container">
  <table class="packet-table">
    <thead>
      <tr>
        <th>No.</th>
        <th>Time</th>
        <th>Source</th>
        <th>Destination</th>
        <th>Protocol</th>
        <th>Length</th>
        <th>Info</th>
      </tr>
    </thead>
    <tbody>
      {#each packets as packet}
        <tr>
          <td>{packet.no}</td>
          <td>{packet.time}</td>
          <td>{packet.source}</td>
          <td>{packet.destination}</td>
          <td class="protocol-cell">{packet.protocol}</td>
          <td>{packet.length}</td>
          <td>{packet.info}</td>
          
        </tr>
      {/each}
    </tbody>
  </table>
</div>


<slot />