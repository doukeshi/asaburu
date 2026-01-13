'use strict';

export const loadWasm = async (wasmUrl) => {
  if (typeof Go === 'undefined') {
    throw new Error('Go runtime is not available.');
  }

  const go = new Go();

  const importObject = {
    ...go.importObject,
    env: {
      ...go.importObject.env,
      print: (message) => {
        console.log(message);
      },
    },
  };

  let obj;
  if ('instantiateStreaming' in WebAssembly) {
    obj = await WebAssembly.instantiateStreaming(fetch(wasmUrl), importObject);
  } else {
    const response = await fetch(wasmUrl);
    const bytes = await response.arrayBuffer();
    obj = await WebAssembly.instantiate(bytes, importObject);
  }
  const wasm = obj.instance;
  go.run(wasm);
  console.log('Go WASM initialized');
  return wasm;
};

export const initCharset = async (element) => {
  const re = window.charset();
  console.log('window.charset(), result: ', re);
  const { data } = JSON.parse(re);
  populateSelect(element, data, data[0]);
};

export const populateSelect = (elements, arr, selectedValue) => {
  const options = arr.map((v) => `<option value="${v}" ${v === selectedValue ? 'selected' : ''}>${v}</option>`).join('');
  const elementsArray = Array.isArray(elements) ? elements : [elements];
  elementsArray.forEach((element) => {
    element.insertAdjacentHTML('beforeend', options);
  });
};

export const Encoding = {
  variants: {
    hex: {
      pattern: '^[0-9a-fA-F]+$',
      bytesize: (s) => s.length / 2,
    },
    base64: {
      pattern: '^[A-Za-z0-9+/=]+$',
      bytesize: (s) => Math.floor((s.length * 3) / 4) - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0),
    },
  },

  validate: function (selectElement, inputElement) {
    const option = selectElement.options[selectElement.selectedIndex];
    const variant = this.variants[option?.value];
    if (!variant) {
      selectElement.classList.add('valid');
      inputElement.classList.add('valid');
      selectElement.setCustomValidity(`Invalid ${selectElement.name}`);
      selectElement.reportValidity();
      return;
    }
    const regex = new RegExp(variant.pattern);
    if (inputElement.value === '' || regex.test(inputElement.value)) {
      selectElement.classList.remove('valid');
      inputElement.classList.remove('valid');
      inputElement.setCustomValidity('');
      return;
    }
    selectElement.classList.add('valid');
    inputElement.classList.add('valid');
    inputElement.setCustomValidity(`Invalid ${inputElement.name}`);
    inputElement.reportValidity();
  },

  valid: function (input, enc) {
    const variant = this.variants[enc];

    const regex = new RegExp(variant.pattern);
    return regex.test(input);
  },
};
