<script lang="ts">
  import { goto } from '$app/navigation';
  import '../styles/app.css';
  import iconStart from '../public/255a48b3c9b5bcd70cf4c919990a2670e27a7c88.png';
  import iconStop from '../public/59e6f6f6e335940070a2975a00f3dc48bd4cf2b3.png';
  import iconReload from '../public/f8756dd4e09e49c50df1b963dfb1d90855953f5d.png';
  import iconSetting from '../public/fc4e67474dba2aed97f75601d0c87d69cecb2e07.png';
  import iconFolder from '../public/16490892d78db858fdc80b35dc3213f699bf5263.png';
  import iconPage from '../public/1513ea29b59643341949efb1762dcf29032eb529.png';
  
</script>

<div class="topbar">
  <div class="topbar-list">
    <span class="topbar-button">File</span>
    <span class="topbar-button">Edit</span>
    <span class="topbar-button">View</span>
    <span class="topbar-button">Go</span>
    <span class="topbar-button">Capture</span>
    <span class="topbar-button">Analyze</span>
    <span class="topbar-button">Statistic</span>
    <span class="topbar-button">Tools</span>
    <span class="topbar-button">Help</span>
  </div>
</div>

<div class="toolbar">
  <div class="toolbar-list">
    <button class="toolbar-button" on:click={() => goto('/mainPage')}>
      <img class="toolbar-img"src={iconStart} alt="Start"> 
    </button>
    <button class="toolbar-button" on:click={() => goto('/')}>
      <img class="toolbar-img"src={iconStop} alt="Start"> 
    </button>
    <button class="toolbar-button">
      <img class="toolbar-img" src={iconReload} alt="Reload">
    </button>
    <button class="toolbar-button">
      <img class="toolbar-img-setting" src={iconSetting} alt="Settings">
    </button>
    <button class="toolbar-button">
      <img class="toolbar-img-setting" src={iconFolder} alt="Folder">
    </button>
    <button class="toolbar-button">
      <img class="toolbar-img-setting" src={iconPage} alt="Page">
    </button>
  </div>
</div>

<slot />