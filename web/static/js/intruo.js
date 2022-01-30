new Vue({
    el: '#app',
    delimiters: ['[[', ']]'],
    data: function() {
        return {
            step: 0,
            page: {
                loading: false,
                title: 'INICIALIZANDO APLICACIÓN',
                currentAnimation: 'animate__fadeInDown',
                alertMessage: null
            },
            form: {
                chromeDriver: {
                    value: {},
                    type: null,
                    message: 'Seleccione el ejecutable de Chrome Driver',
                    label: 'Seleccione su Chrome Driver'
                },
                domain: {
                    value: 'http://wordpress.robertosalasunir.huh.mx/',
                    type: null,
                    message: '',
                    label: 'Ingrese la URL'
                },
                modules: {
                    options: [],
                    value: []
                }
            },
            result: {
                pageOnline: null,
                screenshot: null,
                waitingForResult: false,
                done: false,
                public_id: null
            },
            history: {
                modal: false,
                data: []
            }
        }
    },
    methods: {
        dialogTermAndConditions: function() {
            if (this.form.modules.value.length <= 0) {
                this.$buefy.toast.open({
                    message: 'Debes seleccionar por lo menos un módulo.',
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })
                return
            }
            this.$buefy.dialog.confirm({
                title: 'Renuncia de responsabilidades',
                message: `<p></p><p class="has-text-centered">El uso de esta herramienta (INTRUO) para escanear objetivos sin el consentimiento previo mutuo se considerará ilegal, por tanto, es responsabilidad del usuario final obedecer todas las leyes locales, estatales y federales aplicables. Como desarrollador de este proyecto de investigación no asumo ninguna responsabilidad del mal uso o daño causado por este programa.<br>Este proyecto de investigación no pretende investigar y/o encontrar vulnerabilidades que NO existen o no se encuentran registradas por los distintos medios de divulgación como Internet o fuentes de consulta, sin embargo, al desarrollar o utilizar la herramienta es posible encontrar algún tipo de vulnerabilidad que no se encuentre registrada o que no se encuentre listada en los objetivos específicos de la investigación.</p>`,
                cancelText: 'Cancelar',
                confirmText: 'Acepto e iniciar',
                type: 'is-warning',
                onConfirm: () => this.apiIntruoModules()
            })
        },

        validateUrl: function() {
            if ( !this.isValidUrl(this.form.domain.value) ) {
                this.form.domain.type = 'is-danger'
                this.form.domain.message = 'Tu URL es incorrecta. Intenta colocando el esquema de la URL (http, https). Ejemplo: https://ejemplo.com'
                this.$refs['form__domain'].focus()
                this.$buefy.toast.open({
                    message: 'Tu URL es incorrecta. Intenta colocando el esquema de la URL (http, https).',
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })

                return
            }

            this.page.loading = true
            setTimeout(async ()=>{
                try {
                    const result = await axios.get('/api/modules')
                    if (result.status == 200) {
                        this.step = 2
                        this.changePageTitle(`Objetivo<br>${this.generateURLAnchorElement}`)
                        this.page.loading = false
                        this.form.modules.options = result.data
                    }
                } catch (error) {
                    console.log(error)
                    console.log(error.response)
                    this.$buefy.toast.open({
                        message: 'Error. Intenta resintalando INTRUO.',
                        position: 'is-bottom',
                        type: 'is-warning',
                        duration: 3000
                    })
                }
            }, 1500)
        },

        isValidUrl: function(url_string) {
            let url;
            
            try {
                url = new URL(url_string);
            } catch (_) {
                return false;  
            }
          
            return url.protocol === "http:" || url.protocol === "https:";
        },

        changePageTitle: function(title) {
            this.page.title = title
            if ( this.page.currentAnimation == 'animate__fadeInDown' ) {
                this.page.currentAnimation = 'animate__fadeInUp'
                this.$refs['page__title'].classList.remove('animate__fadeInDown')
                this.$refs['page__title'].classList.add('animate__fadeInUp')
            }
            else if ( this.page.currentAnimation == 'animate__fadeInUp' ) {
                this.page.currentAnimation = 'animate__fadeInDown'
                this.$refs['page__title'].classList.remove('animate__fadeInUp')
                this.$refs['page__title'].classList.add('animate__fadeInDown')
            }
        },

        apiConfigurationInstallDriver: async function() {
            this.page.loading = true
            const file = this.form.chromeDriver.value
            if (file.name === undefined) {
                this.$buefy.toast.open({
                    message: 'No haz seleccionado el driver para que funcione INTRUO.',
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })

                return
            }

            try {
                let formData = new FormData()
                formData.append('driver', file);
                const result = await axios.post('/api/configuration/install/driver', formData, {
                    headers: {
                      'Content-Type': 'multipart/form-data'
                    }
                })

                if (result.status == 200) {
                    setTimeout(() => {
                        this.$buefy.toast.open({
                            message: 'Instalación completada.',
                            position: 'is-bottom',
                            type: 'is-warning',
                            duration: 3000
                        })
                        this.page.loading = false
                        this.page.alertMessage = null
                        this.step = 1
                        this.changePageTitle('INGRESAR OBJETIVO')
                    }, 1500)
                }
            } catch (error) {
                console.log(error.response)
                this.$buefy.toast.open({
                    message: error.response.data.error,
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })
            }
            
        },

        apiIntruoModules: async function() {
            this.page.loading = true
            this.step = 3
            this.changePageTitle(`EJECUTANDO INTRUO EN OBJETIVO<br>${this.generateURLAnchorElement}`)
            
            // Check if page is up
            try {
                const result = await axios.post('/api/module/page_online', {
                    domain: this.form.domain.value
                })

                if (result.status == 200) {
                    this.$refs['logo'].classList.remove('animate__pulse')
                    this.$refs['logo'].classList.remove('animate__slow')
                    this.$refs['logo'].classList.add('animate__flash')
                    this.$refs['logo'].classList.add('animate__slower')
                    this.result.pageOnline = true
                    try {
                        const result = await axios.post('/api/module/screenshot', {
                            domain: this.form.domain.value
                        })
                        if (result.status == 200) {
                            this.result.screenshot = `/static/results/screenshot/${result.data}`
                        }
                    } catch (error) {
                        console.log(error.response)
                    }

                    this.result.waitingForResult = true
        
                    try {
                        const result = await axios.post('/api/modules/run', {
                            domain: this.form.domain.value,
                            modules: this.form.modules.value
                        })
                        if (result.status == 200) {
                            this.page.loading = false
                            this.result.done = true
                            this.result.public_id = result.data
                        }
                    } catch (error) {
                        console.log(error.response)
                    }

                }
            } catch (error) {
                console.log(error.response)
                this.result.pageOnline = false
                this.page.loading = false
                this.$refs['logo'].classList.remove('animate__flash')
                this.$refs['logo'].classList.remove('animate__infinite')
                this.$refs['logo'].classList.remove('animate__slower')
                this.$refs['logo'].classList.add('animate__hinge')
                setTimeout(()=> {
                    this.$refs['logo'].classList.remove('animate__hinge')
                    this.$refs['logo'].classList.add('animate__slower')
                    this.$refs['logo'].classList.add('animate__jackInTheBox')
                }, 2000)
                setTimeout(()=> {
                    this.$refs['logo'].classList.remove('animate__jackInTheBox')
                    this.$refs['logo'].classList.add('animate__infinite')
                    this.$refs['logo'].classList.add('animate__pulse')
                }, 4000)
                this.$buefy.toast.open({
                    message: error.response.data,
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })
            }
        },

        apiIntruoHistory: async function() {
            this.page.loading = true
            try {
                const result = await axios.get('/api/scan/history')
                if (result.status == 200) {
                    this.history.modal = true
                    this.history.data = result.data
                    this.page.loading = false
                }

            } catch (error) {
                console.log(error.response)
                this.$buefy.toast.open({
                    message: 'Error. Intenta reinstalando INTRUO.',
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })
            }
        },

        dialogDeleteIntruoScan: function(public_id, domain) {
            this.$buefy.dialog.confirm({
                title: 'Eliminar escaneo',
                message: `<p class="has-text-centered">¿Estás seguro de querer eliminar el escaneo con dominio <b>${domain}</b> y ID público <b>${public_id}</b>?</p><br><p class="has-text-centered"><b>ESTA ACCIÓN NO SE PUEDE DESHACER</b></p>`,
                cancelText: 'Cancelar',
                confirmText: 'Eliminar',
                type: 'is-danger',
                onConfirm: () => this.deleteIntruoScan(public_id)
            })
        },

        deleteIntruoScan: async function(public_id) {
            this.page.loading = true
            try {
                const result = await axios.delete(`/api/scan/delete/${public_id}`)
                if (result.status == 200) {
                    this.$buefy.toast.open({
                        message: 'Análisis eliminado.',
                        position: 'is-bottom',
                        type: 'is-warning',
                        duration: 3000
                    })

                    this.history.modal = false
                    this.page.loading = false
                }

            } catch (error) {
                console.log(error.response)
                this.$buefy.toast.open({
                    message: 'Error. Intenta reinstalando INTRUO.',
                    position: 'is-bottom',
                    type: 'is-warning',
                    duration: 3000
                })
            }
        }
    },
    computed: {
        generateURLAnchorElement: function() {
            const domain = (new URL(this.form.domain.value))
            return `<small class="has-text-grey"><a href="${this.form.domain.value}" target="_blank">${domain.hostname.toLowerCase()} <span class="icon is-small"><i class="mdi mdi-open-in-new"></i></span></a></small>`
        }
    },
    mounted: async function() {
        this.page.loading = true
        setTimeout(async ()=> {
            this.changePageTitle('ERROR EN CONFIGURACIÓN')
            try {
                const result = await axios.get('/api/check_configuration')
                if (result.status == 200) {
                    this.step = 1
                    this.changePageTitle('INGRESAR OBJETIVO')
                    this.page.loading = false
                    setTimeout(()=> {
                        this.$refs['form__domain'].focus()
                    },1)
                }
            } catch (error) {
                console.log(error.response)
                for (const obj in error.response.data) {
                    if(!error.response.data[obj].result) {
                        this.page.loading = false
                        this.step = 99
                        this.page.alertMessage = error.response.data[obj].error
                    }
                }
            }
        }, 1500)
    }
})