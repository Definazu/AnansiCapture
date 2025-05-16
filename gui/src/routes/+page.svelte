<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import iconShield from '../public/shield.png'
  import iconSpider from '../public/spider.png' 
  let interfaces: string[] = [];
  let error: Error | null = null;
  let showDropdown = false;
  let selectedInterface: string | null = null;
  let captureFilter = '';
  onMount(async () => {
    try {
      const result = await invoke<string[] | string>('get_interfaces');
      interfaces = Array.isArray(result) 
        ? result 
        : result.split(',').map(i => i.trim()).filter(Boolean);
    } catch (e) {
      error = e as Error;
      console.error('Failed to fetch interfaces:', e);
    }
  });

  function toggleDropdown() {
    showDropdown = !showDropdown;
  }

  function selectInterface(interfaceName: string) {
    selectedInterface = interfaceName;
    showDropdown = false;
    console.log('Selected interface:', interfaceName);
  }
</script>

<style>
  @import "../styles/chooseInterfaceMenuStyles.css";
</style>

<div class="logo-item">
  <img src={iconShield} alt="" class="shield-img">
  <img src={iconSpider} alt="" class="spider-img">
</div>

<div class="welcome-text">
  Welcome to AnansiCapture
</div>



<div class="dropdown-container">
  <button class="dropdown-button" on:click={toggleDropdown}>
    {selectedInterface || 'All interfaces shown'}
    <span>{showDropdown ? '▲' : '▼'}</span>
  </button>

  {#if showDropdown}
    <div class="dropdown-list">
      {#if error}
        <div class="error">{error.message}</div>
      {:else if interfaces.length === 0}
        <div class="no-interfaces">No interfaces available</div>
      {:else}
        {#each interfaces as interfaceName}
          <div class="dropdown-item" on:click={() => selectInterface(interfaceName)}>
            {interfaceName}
          </div>
        {/each}
      {/if}
    </div>
  {/if}
</div>
<div class="filter-container">
  <label class="filter-label">Enter the capture filter:</label>
  <input 
    type="text" 
    class="filter-input" 
    bind:value={captureFilter}
    placeholder="Example: tcp port 80"
  />
</div>